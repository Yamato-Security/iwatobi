// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Apache 2.2 / 2.4 error log parser. See design §4.4 and amendments A3, A4, A7.
//!
//! 2.4 (default `ErrorLogFormat`, event and prefork MPMs):
//! `[Sat Oct 24 15:35:39.379473 2026] [core:notice] [pid 1:tid 1] [client 1.2.3.4:5678] AH00051: ...`
//! `[Mon Oct 26 10:11:00.000000 2026] [:error] [pid 1020] [client ::1:50284] PHP Warning:  ..., referer: http://example.com/`
//! with the optional items Apache's `log.c` writes before the message: `file.c(123): ` (debug
//! levels), `(13)Permission denied: ` (APR status) and `[remote 127.0.0.1:8080]` in place of
//! `[client ...]` for backend connections.
//! 2.2: `[Mon Oct 26 10:13:00 2026] [error] [client 2001:db8::1] File does not exist: ...`
//!
//! Lines without a timestamp (child stderr such as `sh: 1: wget: not found`, glibc assertions,
//! startup notices) are continuation events that borrow the previous entry's timestamp.

use super::php::{resolve_naive_logged, tag_php_message};
use super::{LineParser, ParseContext, continuation_event, timestamp};
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use regex::Regex;
use std::sync::LazyLock;

/// Amendment A4, plus the optional `[remote ...]`, `file.c(123): ` and `(13)strerror: ` items.
/// `[remote ...]` is accepted right after `[pid ...]` and at the `[client ...]` position.
static ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^\[(?P<time>\w{3} \w{3} +\d{1,2} \d\d:\d\d:\d\d(?:\.\d{1,6})? \d{4})\] ",
        r"\[(?:(?P<module>[^:\]]*):)?(?P<level>\w+)\]",
        r"(?: \[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\])?",
        r"(?: \[remote (?P<remote>[^\]]+)\])?",
        r"(?: (?P<source>[^\s\[\]():]+\.[a-z]{1,3}\(\d+\)):)?",
        r"(?: (?P<oserr>\(\d+\)[^\[\]]*?):)?",
        r"(?: \[(?:client (?P<client>[^\]]+)|remote (?P<remote2>[^\]]+))\])?",
        r" (?P<msg>.*)$",
    ))
    .expect("static regex")
});

/// Apache 2.4 message codes (`AH00051`).
static ERROR_CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAH\d{5}\b").expect("static regex"));

/// The `, referer: <url>` suffix of the default format (the last occurrence; the value may be
/// empty when the line was trimmed).
static REFERER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<msg>.*), referer:(?: (?P<referer>.*))?$").expect("static regex")
});

/// Whether `line` starts an Apache error log record (2.2 or 2.4 header).
pub fn matches_entry(line: &str) -> bool {
    ENTRY_RE.is_match(line)
}

/// `Sat Oct 24 15:35:39.379473 2026` / `Mon Oct 26 10:13:00 2026` / `Sat Oct  4 ...` → naive.
fn parse_apache_time(s: &str) -> Option<NaiveDateTime> {
    let mut parts = s.split_whitespace();
    let _weekday = parts.next()?;
    let month = timestamp::month_from_abbr(parts.next()?)?;
    let day: u32 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    let year: i32 = parts.next()?.parse().ok()?;
    let (hms, frac) = clock
        .split_once('.')
        .map_or((clock, None), |(a, b)| (a, Some(b)));
    let mut t = hms.split(':');
    let h: u32 = t.next()?.parse().ok()?;
    let m: u32 = t.next()?.parse().ok()?;
    let sec: u32 = t.next()?.parse().ok()?;
    timestamp::naive_from_parts(
        year,
        month,
        day,
        h,
        m,
        sec,
        frac.map_or(0, timestamp::frac_to_nanos),
    )
}

/// `c-ip` (amendment A4): a 2.4 header always logs `ip:port`, so an all-digit suffix after the
/// last `:` is the port; a 2.2 header logs the bare address (`[client 2001:db8::1]`), kept whole.
fn client_ip(client: &str, header24: bool) -> &str {
    if header24
        && let Some((host, port)) = client.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return host;
    }
    client
}

/// Split a trailing `, referer: <url>` off the message.
fn split_referer(msg: &str) -> (&str, Option<&str>) {
    match REFERER_RE.captures(msg) {
        Some(c) => (
            c.name("msg").map_or("", |m| m.as_str()),
            c.name("referer").map(|m| m.as_str()),
        ),
        None => (msg, None),
    }
}

pub struct ApacheErrorParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
    /// A DST ambiguity has already been reported for this file.
    dst_warned: bool,
}

impl ApacheErrorParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self {
            ctx,
            last_ts: None,
            dst_warned: false,
        }
    }
}

impl LineParser for ApacheErrorParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let Some(caps) = ENTRY_RE.captures(line) else {
            // child stderr (`sh: 1: wget: not found`), glibc assertions, startup notices
            let mut ev = continuation_event(
                line,
                &LogSourceTag::APACHE_ERROR,
                &[LogSourceTag::APACHE_ERROR_CANONICAL],
                self.last_ts,
            );
            tag_php_message(&mut ev, line.trim_end());
            self.ctx.finish(&mut ev);
            return Some(ev);
        };
        let group = |name: &str| caps.name(name).map(|m| m.as_str());

        let mut ev = ParsedEvent::new(line, &LogSourceTag::APACHE_ERROR);
        ev.add_tag(LogSourceTag::APACHE_ERROR_CANONICAL);
        match group("time").and_then(parse_apache_time) {
            Some(naive) => {
                let ts = resolve_naive_logged(
                    naive,
                    &self.ctx.tz,
                    &self.ctx.display_name,
                    &mut self.dst_warned,
                );
                ev.timestamp = Some(ts);
                self.last_ts = Some(ts);
            }
            None => {
                // the header matched but the date is impossible: place it like a continuation
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }

        // `[module:level]` is the 2.4 header (the module may be empty: CentOS mod_php logs
        // `[:error]`); a bare `[level]` is 2.2.
        let module = group("module");
        let header24 = module.is_some();
        let client = group("client");
        // split before trimming so that an empty referer (`..., referer: `) is still recognized
        let (message, referer) = split_referer(group("msg").unwrap_or(""));
        let message = message.trim_end();
        let referer = referer.map(str::trim);

        ev.push("module", FieldValue::str_or_null(module.unwrap_or("")));
        ev.push("level", group("level").unwrap_or(""));
        ev.push(
            "pid",
            group("pid").map_or(FieldValue::Null, FieldValue::int_or_null),
        );
        ev.push("client", client);
        ev.push("message", message);
        ev.push(
            "tid",
            group("tid").map_or(FieldValue::Null, FieldValue::int_or_null),
        );
        ev.push(
            "c-ip",
            client.map_or(FieldValue::Null, |c| {
                FieldValue::str_or_null(client_ip(c, header24))
            }),
        );
        ev.push(
            "error_code",
            ERROR_CODE_RE.find(message).map(|m| m.as_str()),
        );
        ev.push(
            "referer",
            referer.map_or(FieldValue::Null, FieldValue::str_or_null),
        );
        if let Some(remote) = group("remote").or_else(|| group("remote2")) {
            ev.push("remote", remote);
        }
        if let Some(source) = group("source") {
            ev.push("source", source);
        }
        if let Some(os_error) = group("oserr") {
            ev.push("os_error", os_error);
        }
        // design §4.4: mod_php's own module (`php`, `php7`, `php8`) is PHP output even when the
        // message does not start with `PHP <type>:`
        if module.is_some_and(|m| m.to_ascii_lowercase().starts_with("php")) {
            ev.add_tag(LogSourceTag::PHP_ERROR_LOG);
        }
        tag_php_message(&mut ev, message);
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{LogFormat, PathHints, TzAssumption, path_hints, sniff_format};
    use std::path::Path;

    fn ctx(name: &str) -> ParseContext {
        ParseContext::new(
            Path::new(name),
            TzAssumption::Fixed(FixedOffset::east_opt(9 * 3600).expect("offset")),
        )
    }

    fn rfc(ev: &ParsedEvent) -> String {
        ev.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default()
    }

    fn fixture(rel: &str) -> Vec<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn keys(ev: &ParsedEvent) -> Vec<&str> {
        ev.fields.iter().map(|(k, _)| k.as_str()).collect()
    }

    fn parse(line: &str) -> ParsedEvent {
        ApacheErrorParser::new(ctx("error.log"))
            .parse_line(line)
            .expect("event")
    }

    const EVENT_MPM: &str = "[Mon Oct 26 10:00:00.123456 2026] [mpm_event:notice] [pid 1000:tid 1000] AH00489: Apache/2.4.62 (Debian) configured -- resuming normal operations";
    const PREFORK: &str = "[Mon Oct 26 10:11:00.000000 2026] [:error] [pid 1020] [client ::1:50284] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0, referer: http://example.com/";
    const PROXY_FCGI: &str = "[Mon Oct 26 10:12:00.000000 2026] [proxy_fcgi:error] [pid 1021:tid 1021] [client 203.0.113.14:51004] AH01071: Got error 'PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0'";
    const APACHE22: &str = "[Mon Oct 26 10:13:00 2026] [error] [client 2001:db8::1] File does not exist: /var/www/favicon.ico";
    const SEGFAULT: &str = "[Sat Oct 24 15:35:39.379473 2026] [core:notice] [pid 1:tid 1] AH00051: child pid 31 exit signal Segmentation fault (11), possible coredump in /etc/apache2";
    const GLIBC: &str = "apache2: ../nptl/pthread_mutex_lock.c:428: __pthread_tpp_change_priority: Assertion `new_prio == -1 || (new_prio >= fifo_min_prio && new_prio <= fifo_max_prio)' failed.";

    #[test]
    fn entry_detection() {
        for l in [
            EVENT_MPM,
            PREFORK,
            PROXY_FCGI,
            APACHE22,
            SEGFAULT,
            "[Sat Oct  4 15:35:39 2026] [notice] Apache/2.2.22 (Debian) configured -- resuming normal operations",
            "[Mon Oct 26 10:13:00 2026] [warn] module php5_module is already loaded, skipping",
            "[Mon Oct 26 10:13:00.1 2026] [ssl:warn] [pid 1] AH01909: server certificate does NOT include an ID which matches the server name",
            "[Mon Oct 26 10:13:00.123456 2026] [core:trace5] [pid 1:tid 1] protocol.c(702): [client ::1:50284] Request received from client: GET / HTTP/1.1",
        ] {
            assert!(matches_entry(l), "{l}");
        }
        for l in [
            "",
            GLIBC,
            "sh: 1: wget: not found",
            "AH00558: apache2: Could not reliably determine the server's fully qualified domain name",
            "2026/10/26 11:00:00 [notice] 2000#2000: using the \"epoll\" event method",
            "[24-Oct-2026 15:35:33 UTC] PHP Fatal error:  x",
            "[Mon Oct 26 10:13:00 2026] no level",
            "[Mon Oct 26 10:13:00.1234567 2026] [core:notice] seven fraction digits",
        ] {
            assert!(!matches_entry(l), "{l}");
        }
    }

    #[test]
    fn event_mpm_line_with_tid() {
        let ev = parse(EVENT_MPM);
        assert_eq!(rfc(&ev), "2026-10-26T10:00:00.123456+09:00");
        assert!(!ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "apache");
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::APACHE_ERROR,
                LogSourceTag::APACHE_ERROR_CANONICAL
            ]
        );
        assert_eq!(
            keys(&ev),
            vec![
                "module",
                "level",
                "pid",
                "client",
                "message",
                "tid",
                "c-ip",
                "error_code",
                "referer"
            ]
        );
        assert_eq!(ev.field_str("module"), Some("mpm_event"));
        assert_eq!(ev.field_str("level"), Some("notice"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(1000)));
        assert_eq!(ev.field("client"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("AH00489: Apache/2.4.62 (Debian) configured -- resuming normal operations")
        );
        assert_eq!(ev.field("tid"), Some(&FieldValue::Int(1000)));
        assert_eq!(ev.field("c-ip"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("error_code"), Some("AH00489"));
        assert_eq!(ev.field("referer"), Some(&FieldValue::Null));
        assert_eq!(ev.raw, EVENT_MPM);
    }

    #[test]
    fn segfault_line_has_error_code() {
        let ev = parse(SEGFAULT);
        assert_eq!(rfc(&ev), "2026-10-24T15:35:39.379473+09:00");
        assert_eq!(ev.field_str("module"), Some("core"));
        assert_eq!(ev.field_str("level"), Some("notice"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(1)));
        assert_eq!(ev.field("tid"), Some(&FieldValue::Int(1)));
        assert_eq!(ev.field_str("error_code"), Some("AH00051"));
        assert_eq!(
            ev.field_str("message"),
            Some(
                "AH00051: child pid 31 exit signal Segmentation fault (11), possible coredump in /etc/apache2"
            )
        );
        assert!(!ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
    }

    #[test]
    fn prefork_mod_php_line_with_empty_module_and_referer() {
        let ev = parse(PREFORK);
        assert_eq!(rfc(&ev), "2026-10-26T10:11:00+09:00");
        assert_eq!(ev.field("module"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("level"), Some("error"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(1020)));
        assert_eq!(ev.field("tid"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("client"), Some("::1:50284"));
        assert_eq!(ev.field_str("c-ip"), Some("::1"));
        assert_eq!(ev.field_str("referer"), Some("http://example.com/"));
        assert_eq!(ev.field("error_code"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some(
                "PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0"
            )
        );
        assert!(ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.tags[0], LogSourceTag::APACHE_ERROR);
        assert_eq!(ev.primary_logsource, "apache");
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(
            ev.field_str("php_message"),
            Some(
                "PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0"
            )
        );
        assert_eq!(ev.field_str("file"), Some("Unknown"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(0)));
    }

    #[test]
    fn proxy_fcgi_php_message_is_unwrapped() {
        let ev = parse(PROXY_FCGI);
        assert_eq!(ev.field_str("module"), Some("proxy_fcgi"));
        assert_eq!(ev.field_str("client"), Some("203.0.113.14:51004"));
        assert_eq!(ev.field_str("c-ip"), Some("203.0.113.14"));
        assert_eq!(ev.field_str("error_code"), Some("AH01071"));
        assert!(ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.field_str("php_type"), Some("Fatal error"));
        assert_eq!(
            ev.field_str("php_message"),
            Some(
                "Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0"
            )
        );
        assert_eq!(ev.field_str("file"), Some("Unknown"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(0)));
        assert!(ev.field_str("message").is_some_and(|m| {
            m.starts_with("AH01071: Got error 'PHP message: ") && m.ends_with("on line 0'")
        }));
        // the same module without a PHP message stays plain apache
        let ev = parse(
            "[Mon Oct 26 10:10:00.000000 2026] [proxy_fcgi:error] [pid 1014:tid 1014] [client 203.0.113.12:51003] AH01071: Got error 'Primary script unknown'",
        );
        assert!(!ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.field("php_type"), None);
    }

    #[test]
    fn apache_22_header() {
        let ev = parse(APACHE22);
        assert_eq!(rfc(&ev), "2026-10-26T10:13:00+09:00");
        assert_eq!(ev.field("module"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("level"), Some("error"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
        assert_eq!(ev.field("tid"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("client"), Some("2001:db8::1"));
        assert_eq!(
            ev.field_str("c-ip"),
            Some("2001:db8::1"),
            "2.2 logs no port"
        );
        assert_eq!(
            ev.field_str("message"),
            Some("File does not exist: /var/www/favicon.ico")
        );
        assert_eq!(ev.field("error_code"), Some(&FieldValue::Null));
        assert_eq!(ev.field("referer"), Some(&FieldValue::Null));
        assert!(!ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        // 2.2 PHP line with a referer
        let ev = parse(
            "[Mon Oct 26 10:13:00 2026] [error] [client 1.2.3.4] PHP Notice:  Undefined variable: x in /var/www/x.php on line 3, referer: http://x/",
        );
        assert_eq!(ev.field_str("client"), Some("1.2.3.4"));
        assert_eq!(ev.field_str("c-ip"), Some("1.2.3.4"));
        assert_eq!(ev.field_str("referer"), Some("http://x/"));
        assert_eq!(ev.field_str("php_type"), Some("Notice"));
        assert_eq!(ev.field_str("file"), Some("/var/www/x.php"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(3)));
        // 2.2 without a client
        let ev = parse(
            "[Mon Oct 26 10:13:00 2026] [notice] Apache/2.2.22 (Debian) configured -- resuming normal operations",
        );
        assert_eq!(ev.field("client"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("Apache/2.2.22 (Debian) configured -- resuming normal operations")
        );
    }

    #[test]
    fn client_ip_port_stripping_rules() {
        assert_eq!(client_ip("::1:50284", true), "::1");
        assert_eq!(client_ip("2001:db8::1:50284", true), "2001:db8::1");
        assert_eq!(client_ip("203.0.113.10:51000", true), "203.0.113.10");
        assert_eq!(client_ip("203.0.113.10", true), "203.0.113.10");
        assert_eq!(client_ip("2001:db8::1", false), "2001:db8::1");
        assert_eq!(client_ip("203.0.113.10:51000", false), "203.0.113.10:51000");
        assert_eq!(client_ip("1.2.3.4:abc", true), "1.2.3.4:abc");
        assert_eq!(client_ip(":50284", true), ":50284");
        let ev = parse(
            "[Mon Oct 26 10:09:00.000000 2026] [authz_core:error] [pid 1013:tid 1013] [client 2001:db8::1:51002] AH01630: client denied by server configuration: /var/www/html/.git",
        );
        assert_eq!(ev.field_str("client"), Some("2001:db8::1:51002"));
        assert_eq!(ev.field_str("c-ip"), Some("2001:db8::1"));
        assert_eq!(ev.field_str("error_code"), Some("AH01630"));
    }

    #[test]
    fn php_module_lines_are_tagged_even_without_a_php_prefix() {
        let ev = parse(
            "[Mon Oct 26 10:06:00.500000 2026] [php:error] [pid 1011:tid 1011] [client 203.0.113.10:51000] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
        );
        assert_eq!(rfc(&ev), "2026-10-26T10:06:00.500+09:00");
        assert_eq!(ev.field_str("module"), Some("php"));
        assert_eq!(ev.field_str("c-ip"), Some("203.0.113.10"));
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::APACHE_ERROR,
                LogSourceTag::APACHE_ERROR_CANONICAL,
                LogSourceTag::PHP_ERROR_LOG
            ]
        );
        assert_eq!(ev.field_str("php_type"), Some("Fatal error"));
        let ev = parse(
            "[Mon Oct 26 10:06:00 2026] [php7:notice] [pid 1011] [client 1.2.3.4:5] script '/var/www/html/x.php' not found or unable to stat",
        );
        assert!(ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.field("php_type"), None);
        let ev = parse(
            "[Mon Oct 26 10:06:00 2026] [core:notice] [pid 1] AH00094: Command line: '/usr/sbin/apache2'",
        );
        assert!(!ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
    }

    #[test]
    fn optional_remote_source_and_os_error_items() {
        let ev = parse(
            "[Mon Oct 26 10:13:00.123456 2026] [proxy_http:error] [pid 1234:tid 5678] (104)Connection reset by peer: [remote 127.0.0.1:8080] AH01102: error reading status line from remote server 127.0.0.1:8080, referer: http://example.com/app",
        );
        assert_eq!(ev.field_str("module"), Some("proxy_http"));
        assert_eq!(ev.field("client"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field("c-ip"),
            Some(&FieldValue::Null),
            "the backend is not the client"
        );
        assert_eq!(ev.field_str("remote"), Some("127.0.0.1:8080"));
        assert_eq!(
            ev.field_str("os_error"),
            Some("(104)Connection reset by peer")
        );
        assert_eq!(ev.field_str("error_code"), Some("AH01102"));
        assert_eq!(ev.field_str("referer"), Some("http://example.com/app"));
        assert_eq!(
            ev.field_str("message"),
            Some("AH01102: error reading status line from remote server 127.0.0.1:8080")
        );
        assert_eq!(ev.field("source"), None);
        // [remote] directly after [pid]
        let ev = parse(
            "[Mon Oct 26 10:13:00.123456 2026] [ssl:info] [pid 1234:tid 5678] [remote 203.0.113.5:443] AH01964: Connection to child 1 established (server example.com:443)",
        );
        assert_eq!(ev.field_str("remote"), Some("203.0.113.5:443"));
        assert_eq!(ev.field("client"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("error_code"), Some("AH01964"));
        // APR status before the client
        let ev = parse(
            "[Mon Oct 26 10:13:00.123456 2026] [core:error] [pid 29657:tid 140144123] (13)Permission denied: [client 192.168.1.1:51000] AH00035: access to /foo denied (filesystem path '/var/www/foo') because search permissions are missing on a component of the path",
        );
        assert_eq!(ev.field_str("os_error"), Some("(13)Permission denied"));
        assert_eq!(ev.field_str("client"), Some("192.168.1.1:51000"));
        assert_eq!(ev.field_str("c-ip"), Some("192.168.1.1"));
        assert_eq!(ev.field_str("error_code"), Some("AH00035"));
        assert!(
            ev.field_str("message")
                .is_some_and(|m| m.starts_with("AH00035: access to /foo denied"))
        );
        // APR status without a client keeps the message intact
        let ev = parse(
            "[Mon Oct 26 10:13:00.123456 2026] [proxy:error] [pid 1:tid 1] (111)Connection refused: AH00957: HTTP: attempt to connect to 127.0.0.1:8080 (localhost) failed",
        );
        assert_eq!(ev.field_str("os_error"), Some("(111)Connection refused"));
        assert_eq!(
            ev.field_str("message"),
            Some("AH00957: HTTP: attempt to connect to 127.0.0.1:8080 (localhost) failed")
        );
        // debug source file item
        let ev = parse(
            "[Mon Oct 26 10:13:00.123456 2026] [core:trace5] [pid 1:tid 1] protocol.c(702): [client ::1:50284] Request received from client: GET / HTTP/1.1",
        );
        assert_eq!(ev.field_str("level"), Some("trace5"));
        assert_eq!(ev.field_str("source"), Some("protocol.c(702)"));
        assert_eq!(ev.field_str("client"), Some("::1:50284"));
        assert_eq!(ev.field_str("c-ip"), Some("::1"));
        assert_eq!(
            ev.field_str("message"),
            Some("Request received from client: GET / HTTP/1.1")
        );
        let ev = parse(
            "[Mon Oct 26 10:13:00.123456 2026] [proxy_fcgi:debug] [pid 1:tid 1] mod_proxy_fcgi.c(1104): [client 1.2.3.4:5] AH01076: url: fcgi://localhost/var/www/html/index.php proxyname: (null) proxyport: 0",
        );
        assert_eq!(ev.field_str("source"), Some("mod_proxy_fcgi.c(1104)"));
        assert_eq!(ev.field_str("error_code"), Some("AH01076"));
        // a message that merely starts with a parenthesised word is not an APR status
        let ev = parse(
            "[Mon Oct 26 10:13:00 2026] [core:notice] [pid 1:tid 1] (re)loading configuration: done",
        );
        assert_eq!(ev.field("os_error"), None);
        assert_eq!(
            ev.field_str("message"),
            Some("(re)loading configuration: done")
        );
    }

    #[test]
    fn untimestamped_lines_are_continuations_with_php_detection() {
        let mut p = ApacheErrorParser::new(ctx("error.log"));
        // before any entry: no timestamp at all
        let ev = p.parse_line("sh: 1: wget: not found").expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "apache");
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::APACHE_ERROR,
                LogSourceTag::APACHE_ERROR_CANONICAL
            ]
        );
        assert_eq!(keys(&ev), vec!["message"]);
        assert_eq!(ev.field_str("message"), Some("sh: 1: wget: not found"));

        let first = p.parse_line(SEGFAULT).expect("event");
        let ev = p.parse_line(GLIBC).expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert!(!ev.tz_explicit);
        assert_eq!(ev.field_str("message"), Some(GLIBC));
        assert!(!ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));

        let ev = p
            .parse_line("sh: 1: cannot create /var/www/html/p1: Read-only file system")
            .expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);

        // a PHP CLI line copied to stderr gets the PHP tag and fields
        let ev = p
            .parse_line("PHP Warning:  file_get_contents(http://1.2.3.4/x): Failed to open stream in Command line code on line 1")
            .expect("event");
        assert!(ev.timestamp_inferred);
        assert!(ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(ev.field_str("file"), Some("Command line code"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(1)));

        // the next entry resets the borrowed timestamp
        let next = p.parse_line(APACHE22).expect("event");
        let ev = p.parse_line("sh: 1: wget: not found").expect("event");
        assert_eq!(ev.timestamp, next.timestamp);
        assert_ne!(ev.timestamp, first.timestamp);

        assert!(p.parse_line("").is_none());
        assert!(p.parse_line("  \t ").is_none());
        assert!(p.parse_line("\r").is_none());
    }

    #[test]
    fn time_shapes() {
        assert_eq!(
            parse_apache_time("Sat Oct 24 15:35:39.379473 2026").map(|t| t.to_string()),
            Some("2026-10-24 15:35:39.379473".to_string())
        );
        assert_eq!(
            parse_apache_time("Mon Oct 26 10:13:00 2026").map(|t| t.to_string()),
            Some("2026-10-26 10:13:00".to_string())
        );
        assert_eq!(
            parse_apache_time("Sat Oct  4 05:06:07 2026").map(|t| t.to_string()),
            Some("2026-10-04 05:06:07".to_string())
        );
        assert_eq!(parse_apache_time("Sat Xyz 24 15:35:39 2026"), None);
        assert_eq!(parse_apache_time("Sat Oct 32 15:35:39 2026"), None);
        assert_eq!(parse_apache_time("Sat Oct 24 25:35:39 2026"), None);
        assert_eq!(parse_apache_time("Sat Oct 24 15:35 2026"), None);
        let ev = parse("[Sat Oct  4 05:06:07.5 2026] [core:notice] [pid 1:tid 1] AH00094: x");
        assert_eq!(rfc(&ev), "2026-10-04T05:06:07.500+09:00");
        // a header with an impossible date keeps its fields and borrows the timestamp
        let mut p = ApacheErrorParser::new(ctx("error.log"));
        let first = p.parse_line(SEGFAULT).expect("event");
        let ev = p
            .parse_line(
                "[Sat Oct 32 15:35:39.379473 2026] [core:notice] [pid 1:tid 1] AH00051: bad day",
            )
            .expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.field_str("error_code"), Some("AH00051"));
        assert_eq!(ev.field_str("module"), Some("core"));
    }

    #[test]
    fn timezone_assumptions_apply_to_the_naive_time() {
        let utc = ParseContext::new(
            Path::new("error.log"),
            TzAssumption::Fixed(FixedOffset::east_opt(0).expect("utc")),
        );
        let ev = ApacheErrorParser::new(utc)
            .parse_line(SEGFAULT)
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-24T15:35:39.379473+00:00");
        let berlin = ParseContext::new(
            Path::new("error.log"),
            TzAssumption::Named(chrono_tz::Europe::Berlin),
        );
        let ev = ApacheErrorParser::new(berlin)
            .parse_line(SEGFAULT)
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-24T15:35:39.379473+02:00");
        assert!(!ev.tz_explicit);
    }

    #[test]
    fn dst_ambiguity_is_reported_once_per_file() {
        crate::errorlog::set_quiet(true);
        let berlin = ParseContext::new(
            Path::new("error.log"),
            TzAssumption::Named(chrono_tz::Europe::Berlin),
        );
        let mut p = ApacheErrorParser::new(berlin);
        let ev = p
            .parse_line("[Sun Oct 25 02:30:00.000000 2026] [core:notice] [pid 1:tid 1] AH00094: x")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-25T02:30:00+02:00");
        assert!(p.dst_warned);
    }

    #[test]
    fn referer_split_takes_the_last_occurrence() {
        assert_eq!(split_referer("msg"), ("msg", None));
        assert_eq!(
            split_referer("a, referer: http://x/, referer: http://y/"),
            ("a, referer: http://x/", Some("http://y/"))
        );
        assert_eq!(split_referer("a, referer: "), ("a", Some("")));
        assert_eq!(split_referer("a, referer:"), ("a", None));
        assert_eq!(split_referer("a, referer:x"), ("a, referer:x", None));
        for line in [
            "[Mon Oct 26 10:13:00 2026] [error] [client 1.2.3.4] x, referer: ",
            "[Mon Oct 26 10:13:00 2026] [error] [client 1.2.3.4] x, referer:",
        ] {
            let ev = parse(line);
            assert_eq!(ev.field("referer"), Some(&FieldValue::Null), "{line}");
            assert_eq!(ev.field_str("message"), Some("x"), "{line}");
        }
        let ev =
            parse("[Mon Oct 26 10:13:00 2026] [error] [client 1.2.3.4] x, referer: http://y/  ");
        assert_eq!(ev.field_str("referer"), Some("http://y/"));
        assert_eq!(ev.field_str("message"), Some("x"));
    }

    #[test]
    fn context_tags_and_hostname_are_applied() {
        let mut c = ctx("error.log");
        c.extra_tags = vec![LogSourceTag::WEBSERVER];
        c.hostname_hint = Some("web01".to_string());
        let mut p = ApacheErrorParser::new(c);
        let ev = p.parse_line(SEGFAULT).expect("event");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert!(ev.tags.contains(&LogSourceTag::WEBSERVER));
        let ev = p.parse_line("sh: 1: wget: not found").expect("event");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert!(ev.tags.contains(&LogSourceTag::WEBSERVER));
    }

    #[test]
    fn web_fixture_parses_every_line() {
        let lines = fixture("test_files/web/apache2/error.log");
        assert_eq!(lines.len(), 11);
        let mut p = ApacheErrorParser::new(ctx("test_files/web/apache2/error.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 11);
        let inferred: Vec<&str> = events
            .iter()
            .filter(|e| e.timestamp_inferred)
            .map(|e| e.raw.as_str())
            .collect();
        assert_eq!(inferred, vec![GLIBC]);
        assert_eq!(events[4].timestamp, events[3].timestamp);
        assert_eq!(
            events
                .iter()
                .filter(|e| e.tags.contains(&LogSourceTag::PHP_ERROR_LOG))
                .count(),
            3
        );
        assert!(
            events
                .iter()
                .all(|e| e.tags[0] == LogSourceTag::APACHE_ERROR
                    && e.tags[1] == LogSourceTag::APACHE_ERROR_CANONICAL)
        );
        assert!(events.iter().all(|e| !e.tz_explicit));
        assert_eq!(events[2].field_str("error_code"), Some("AH00051"));
        assert_eq!(events[8].field("module"), Some(&FieldValue::Null));
        assert_eq!(events[8].field_str("c-ip"), Some("::1"));
        assert_eq!(events[9].field_str("php_type"), Some("Fatal error"));
        assert_eq!(events[10].field_str("client"), Some("2001:db8::1"));
        assert_eq!(rfc(&events[0]), "2026-10-26T10:00:00.123456+09:00");
        assert_eq!(rfc(&events[10]), "2026-10-26T10:13:00+09:00");
    }

    #[test]
    fn php2shell_fixture_parses_every_line() {
        let lines = fixture("test_files/php2shell/apache2/error.log");
        assert_eq!(lines.len(), 93);
        let mut p = ApacheErrorParser::new(ctx("test_files/php2shell/apache2/error.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 93);
        let shell: Vec<&ParsedEvent> = events
            .iter()
            .filter(|e| e.raw.starts_with("sh: "))
            .collect();
        assert_eq!(shell.len(), 29);
        assert!(
            shell
                .iter()
                .all(|e| e.timestamp_inferred && e.timestamp.is_some())
        );
        assert!(
            shell
                .iter()
                .all(|e| e.field_str("message") == Some(e.raw.as_str()))
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.field_str("error_code") == Some("AH00051"))
                .count(),
            62
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e
                    .field_str("message")
                    .is_some_and(|m| m.contains("exit signal Abort (6)")))
                .count(),
            7
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e
                    .field_str("message")
                    .is_some_and(|m| m.contains("Segmentation fault (11)")))
                .count(),
            55
        );
        // the first shell lines borrow the AH00094 start-up notice's timestamp
        assert_eq!(rfc(&events[2]), "2026-10-24T13:00:00.000100+09:00");
        assert_eq!(events[2].timestamp, events[1].timestamp);
        assert!(
            events
                .iter()
                .all(|e| !e.tags.contains(&LogSourceTag::PHP_ERROR_LOG))
        );
        assert!(events.iter().all(|e| e.hostname.is_none()));
    }

    #[test]
    fn sniffing_recognizes_apache_error_logs() {
        let web = fixture("test_files/web/apache2/error.log");
        assert_eq!(
            sniff_format(
                &web,
                &path_hints(Path::new("test_files/web/apache2/error.log"))
            ),
            Some(LogFormat::ApacheError)
        );
        assert_eq!(
            sniff_format(&web, &PathHints::default()),
            Some(LogFormat::ApacheError)
        );
        let honeypot = fixture("test_files/php2shell/apache2/error.log");
        assert_eq!(
            sniff_format(&honeypot, &PathHints::default()),
            Some(LogFormat::ApacheError)
        );
    }
}
