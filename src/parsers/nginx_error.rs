// Copyright (C) 2026 Yamato Security
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

//! nginx error log parser. See design §4.5 and amendments A3, A7, A8.
//!
//! `2026/10/24 15:35:39 [error] 1234#1234: *5 upstream prematurely closed connection ..., client: 1.2.3.4, server: _, request: "POST /index.php HTTP/1.1", upstream: "fastcgi://unix:/run/php/php8.3-fpm.sock:", host: "example.com", referrer: "..."`
//!
//! The trailing `, key: value` pairs are peeled off from the right (quote-aware: a quoted request
//! or host may contain commas and escaped quotes); what remains is `message`. Lines without the
//! timestamp header (`nginx: [emerg] ...` startup errors, multi-line output) are continuation
//! events that borrow the previous entry's timestamp.

use super::php::{resolve_naive_logged, tag_php_message};
use super::{LineParser, ParseContext, continuation_event};
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use regex::Regex;
use std::sync::LazyLock;

/// Amendment A8: the entry header.
static ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<time>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+):(?: \*(?P<conn>\d+))? (?P<rest>.*)$",
    )
    .expect("static regex")
});

/// One trailing `, key: value` pair. Anchored at the end and matched leftmost-first, so a quoted
/// value that itself contains `, host: ...` is never split.
static PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#", (?P<key>client|server|request|upstream|host|referrer|subrequest): (?P<val>"(?:[^"\\]|\\.)*"|[^,]*)$"#,
    )
    .expect("static regex")
});

/// Whether `line` starts an nginx error log record.
pub fn matches_entry(line: &str) -> bool {
    ENTRY_RE.is_match(line)
}

/// The `, key: value` pairs nginx appends to a request-scoped message.
#[derive(Debug, Default, PartialEq, Eq)]
struct Pairs<'a> {
    client: Option<&'a str>,
    server: Option<&'a str>,
    request: Option<&'a str>,
    upstream: Option<&'a str>,
    host: Option<&'a str>,
    referrer: Option<&'a str>,
    subrequest: Option<&'a str>,
}

/// Remove the outer double quotes of a quoted value (the content is kept as written).
fn unquote(v: &str) -> &str {
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
}

/// Peel the trailing pairs off `rest` from the right until none is left; a repeated key belongs
/// to the message text and stops the peeling.
fn split_pairs(rest: &str) -> (&str, Pairs<'_>) {
    let mut pairs = Pairs::default();
    let mut msg = rest;
    while let Some(c) = PAIR_RE.captures(msg) {
        let (Some(whole), Some(key), Some(val)) = (c.get(0), c.name("key"), c.name("val")) else {
            break;
        };
        let slot = match key.as_str() {
            "client" => &mut pairs.client,
            "server" => &mut pairs.server,
            "request" => &mut pairs.request,
            "upstream" => &mut pairs.upstream,
            "host" => &mut pairs.host,
            "referrer" => &mut pairs.referrer,
            "subrequest" => &mut pairs.subrequest,
            _ => break,
        };
        if slot.is_some() {
            break;
        }
        *slot = Some(unquote(val.as_str()));
        msg = &msg[..whole.start()];
    }
    (msg.trim_end(), pairs)
}

fn opt(v: Option<&str>) -> FieldValue {
    v.map_or(FieldValue::Null, FieldValue::str_or_null)
}

pub struct NginxErrorParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
    /// A DST ambiguity has already been reported for this file.
    dst_warned: bool,
}

impl NginxErrorParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self {
            ctx,
            last_ts: None,
            dst_warned: false,
        }
    }
}

impl LineParser for NginxErrorParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let Some(caps) = ENTRY_RE.captures(line) else {
            let mut ev = continuation_event(
                line,
                &LogSourceTag::NGINX_ERROR,
                &[LogSourceTag::NGINX_ERROR_CANONICAL],
                self.last_ts,
            );
            tag_php_message(&mut ev, line.trim_end());
            self.ctx.finish(&mut ev);
            return Some(ev);
        };
        let group = |name: &str| caps.name(name).map(|m| m.as_str());

        let mut ev = ParsedEvent::new(line, &LogSourceTag::NGINX_ERROR);
        ev.add_tag(LogSourceTag::NGINX_ERROR_CANONICAL);
        match group("time").and_then(|t| NaiveDateTime::parse_from_str(t, "%Y/%m/%d %H:%M:%S").ok())
        {
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
        let (message, pairs) = split_pairs(group("rest").unwrap_or("").trim_end());

        ev.push("level", group("level").unwrap_or(""));
        ev.push(
            "pid",
            group("pid").map_or(FieldValue::Null, FieldValue::int_or_null),
        );
        ev.push("client", opt(pairs.client));
        ev.push("request", opt(pairs.request));
        ev.push("upstream", opt(pairs.upstream));
        ev.push("message", message);
        ev.push(
            "tid",
            group("tid").map_or(FieldValue::Null, FieldValue::int_or_null),
        );
        ev.push(
            "connection",
            group("conn").map_or(FieldValue::Null, FieldValue::int_or_null),
        );
        ev.push("server", opt(pairs.server));
        ev.push("host", opt(pairs.host));
        ev.push("referrer", opt(pairs.referrer));
        ev.push("c-ip", opt(pairs.client));
        if let Some(sub) = pairs.subrequest {
            ev.push("subrequest", sub);
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
        NginxErrorParser::new(ctx("error.log"))
            .parse_line(line)
            .expect("event")
    }

    const NOTICE: &str = "2026/10/26 11:00:00 [notice] 2000#2000: using the \"epoll\" event method";
    const UPSTREAM: &str = "2026/10/26 11:01:00 [error] 2001#2001: *15 upstream prematurely closed connection while reading response header from upstream, client: 203.0.113.10, server: _, request: \"POST /index.php HTTP/1.1\", upstream: \"fastcgi://unix:/run/php/php8.3-fpm.sock:\", host: \"example.com\"";
    const CORE_DUMP: &str = "2026/10/26 11:01:01 [alert] 2000#2000: worker process 2001 exited on signal 6 (core dumped)";
    const FAVICON: &str = "2026/10/26 11:02:00 [error] 2002#2002: *16 open() \"/var/www/html/favicon.ico\" failed (2: No such file or directory), client: 203.0.113.11, server: _, request: \"GET /favicon.ico HTTP/1.1\", host: \"example.com\", referrer: \"http://example.com/\"";
    const FASTCGI_PHP: &str = "2026/10/26 11:01:00 [error] 2001#2001: *15 FastCGI sent in stderr: \"PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0\" while reading response header from upstream, client: 198.51.100.99, server: _, request: \"POST /index.php?a=1,b=2 HTTP/1.1\", upstream: \"fastcgi://unix:/run/php/php8.3-fpm.sock:\", host: \"203.0.113.30, evil.example\"";

    #[test]
    fn entry_detection() {
        for l in [
            NOTICE,
            UPSTREAM,
            CORE_DUMP,
            FAVICON,
            FASTCGI_PHP,
            "2026/10/26 11:00:00 [emerg] 1#1: bind() to 0.0.0.0:80 failed (98: Address already in use)",
            "2026/10/26 11:00:00 [crit] 1#1: *1 SSL_do_handshake() failed, client: 1.2.3.4, server: 0.0.0.0:443",
        ] {
            assert!(matches_entry(l), "{l}");
        }
        for l in [
            "",
            "nginx: [emerg] unknown directive \"foo\" in /etc/nginx/nginx.conf:10",
            "sh: 1: wget: not found",
            "[Mon Oct 26 10:13:00 2026] [error] [client 2001:db8::1] File does not exist",
            "2026-10-26 11:00:00 [notice] 2000#2000: iso date",
            "2026/10/26 11:00:00 [notice] 2000: no tid",
            "2026/10/26 11:00:00 notice 2000#2000: no brackets",
        ] {
            assert!(!matches_entry(l), "{l}");
        }
    }

    #[test]
    fn notice_without_pairs() {
        let ev = parse(NOTICE);
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00+09:00");
        assert!(!ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "nginx");
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::NGINX_ERROR,
                LogSourceTag::NGINX_ERROR_CANONICAL
            ]
        );
        assert_eq!(
            keys(&ev),
            vec![
                "level",
                "pid",
                "client",
                "request",
                "upstream",
                "message",
                "tid",
                "connection",
                "server",
                "host",
                "referrer",
                "c-ip"
            ]
        );
        assert_eq!(ev.field_str("level"), Some("notice"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(2000)));
        assert_eq!(ev.field("tid"), Some(&FieldValue::Int(2000)));
        assert_eq!(ev.field("connection"), Some(&FieldValue::Null));
        assert_eq!(ev.field("client"), Some(&FieldValue::Null));
        assert_eq!(ev.field("c-ip"), Some(&FieldValue::Null));
        assert_eq!(ev.field("request"), Some(&FieldValue::Null));
        assert_eq!(ev.field("upstream"), Some(&FieldValue::Null));
        assert_eq!(ev.field("server"), Some(&FieldValue::Null));
        assert_eq!(ev.field("host"), Some(&FieldValue::Null));
        assert_eq!(ev.field("referrer"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("using the \"epoll\" event method")
        );
        assert_eq!(ev.raw, NOTICE);
    }

    #[test]
    fn upstream_error_with_pairs() {
        let ev = parse(UPSTREAM);
        assert_eq!(rfc(&ev), "2026-10-26T11:01:00+09:00");
        assert_eq!(ev.field_str("level"), Some("error"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(2001)));
        assert_eq!(ev.field("tid"), Some(&FieldValue::Int(2001)));
        assert_eq!(ev.field("connection"), Some(&FieldValue::Int(15)));
        assert_eq!(ev.field_str("client"), Some("203.0.113.10"));
        assert_eq!(ev.field_str("c-ip"), Some("203.0.113.10"));
        assert_eq!(ev.field_str("server"), Some("_"));
        assert_eq!(ev.field_str("request"), Some("POST /index.php HTTP/1.1"));
        assert_eq!(
            ev.field_str("upstream"),
            Some("fastcgi://unix:/run/php/php8.3-fpm.sock:")
        );
        assert_eq!(ev.field_str("host"), Some("example.com"));
        assert_eq!(ev.field("referrer"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some(
                "upstream prematurely closed connection while reading response header from upstream"
            )
        );
        assert_eq!(ev.field("subrequest"), None);
        assert!(!ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
    }

    #[test]
    fn core_dump_alert_is_a_normal_entry() {
        let ev = parse(CORE_DUMP);
        assert_eq!(ev.field_str("level"), Some("alert"));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(2000)));
        assert_eq!(ev.field("connection"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("worker process 2001 exited on signal 6 (core dumped)")
        );
    }

    #[test]
    fn referrer_pair() {
        let ev = parse(FAVICON);
        assert_eq!(ev.field("connection"), Some(&FieldValue::Int(16)));
        assert_eq!(ev.field_str("client"), Some("203.0.113.11"));
        assert_eq!(ev.field_str("request"), Some("GET /favicon.ico HTTP/1.1"));
        assert_eq!(ev.field_str("host"), Some("example.com"));
        assert_eq!(ev.field_str("referrer"), Some("http://example.com/"));
        assert_eq!(ev.field("upstream"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("open() \"/var/www/html/favicon.ico\" failed (2: No such file or directory)")
        );
    }

    #[test]
    fn fastcgi_php_message_with_commas_inside_quoted_values() {
        let ev = parse(FASTCGI_PHP);
        assert_eq!(rfc(&ev), "2026-10-26T11:01:00+09:00");
        assert_eq!(ev.field_str("client"), Some("198.51.100.99"));
        assert_eq!(ev.field_str("c-ip"), Some("198.51.100.99"));
        assert_eq!(ev.field_str("server"), Some("_"));
        assert_eq!(
            ev.field_str("request"),
            Some("POST /index.php?a=1,b=2 HTTP/1.1")
        );
        assert_eq!(
            ev.field_str("upstream"),
            Some("fastcgi://unix:/run/php/php8.3-fpm.sock:")
        );
        assert_eq!(ev.field_str("host"), Some("203.0.113.30, evil.example"));
        let message = ev.field_str("message").expect("message");
        assert!(message.starts_with("FastCGI sent in stderr: \"PHP message: PHP Fatal error:"));
        assert!(message.ends_with("on line 0\" while reading response header from upstream"));
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::NGINX_ERROR,
                LogSourceTag::NGINX_ERROR_CANONICAL,
                LogSourceTag::PHP_ERROR_LOG
            ]
        );
        assert_eq!(ev.primary_logsource, "nginx");
        assert_eq!(ev.field_str("php_type"), Some("Fatal error"));
        assert_eq!(
            ev.field_str("php_message"),
            Some(
                "Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"
            )
        );
        assert_eq!(ev.field_str("file"), Some("Unknown"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(0)));
    }

    #[test]
    fn pair_peeling_is_quote_aware() {
        // escaped quotes and commas inside the request
        let (msg, pairs) = split_pairs(
            r#"recv() failed, client: 1.2.3.4, server: example.com, request: "GET /?q=\"x\",y HTTP/1.1", host: "h""#,
        );
        assert_eq!(msg, "recv() failed");
        assert_eq!(pairs.client, Some("1.2.3.4"));
        assert_eq!(pairs.server, Some("example.com"));
        assert_eq!(pairs.request, Some(r#"GET /?q=\"x\",y HTTP/1.1"#));
        assert_eq!(pairs.host, Some("h"));
        // a key name inside a quoted value is not a pair
        let (msg, pairs) = split_pairs(r#"x, request: "GET /?a, client: b HTTP/1.1", host: "h""#);
        assert_eq!(msg, "x");
        assert_eq!(pairs.request, Some("GET /?a, client: b HTTP/1.1"));
        assert_eq!(pairs.client, None);
        assert_eq!(pairs.host, Some("h"));
        // an unescaped quote inside the value falls back to the comma rule
        let (msg, pairs) = split_pairs(r#"x, request: "GET /?q=" HTTP/1.1""#);
        assert_eq!(msg, "x");
        assert_eq!(pairs.request, Some(r#"GET /?q=" HTTP/1.1"#));
        // an unknown trailing key (mail module `login`) stops the peeling
        let (msg, pairs) = split_pairs(r#"y, subrequest: "/auth", upstream: "", login: "u""#);
        assert_eq!(msg, r#"y, subrequest: "/auth", upstream: "", login: "u""#);
        assert_eq!(pairs, Pairs::default());
        // subrequest and an empty quoted value
        let (msg, pairs) = split_pairs(r#"y, subrequest: "/auth", upstream: """#);
        assert_eq!(msg, "y");
        assert_eq!(pairs.subrequest, Some("/auth"));
        assert_eq!(pairs.upstream, Some(""));
        // a repeated key belongs to the message
        let (msg, pairs) = split_pairs("a, client: 1.1.1.1, client: 2.2.2.2");
        assert_eq!(msg, "a, client: 1.1.1.1");
        assert_eq!(pairs.client, Some("2.2.2.2"));
        // nothing to peel
        assert_eq!(split_pairs("plain message").0, "plain message");
        assert_eq!(split_pairs("").0, "");
        // ipv6 client; stream-module text without `: ` is left alone
        let (msg, pairs) = split_pairs("z, bytes from/to client:1/2, client: 2001:db8::1");
        assert_eq!(msg, "z, bytes from/to client:1/2");
        assert_eq!(pairs.client, Some("2001:db8::1"));
    }

    #[test]
    fn subrequest_and_empty_values_as_fields() {
        let ev = parse(
            "2026/10/26 11:03:00 [error] 2003#2003: *17 auth request unexpected status: 500, client: 1.2.3.4, server: _, request: \"GET /secret HTTP/1.1\", subrequest: \"/auth\", upstream: \"http://127.0.0.1:9000/auth\", host: \"\"",
        );
        assert_eq!(ev.field_str("subrequest"), Some("/auth"));
        assert_eq!(
            ev.field("host"),
            Some(&FieldValue::Null),
            "empty quoted value"
        );
        assert_eq!(ev.field_str("upstream"), Some("http://127.0.0.1:9000/auth"));
        assert_eq!(
            ev.field_str("message"),
            Some("auth request unexpected status: 500")
        );
        assert_eq!(keys(&ev).last().copied(), Some("subrequest"));
    }

    #[test]
    fn continuations_and_blank_lines() {
        let mut p = NginxErrorParser::new(ctx("error.log"));
        assert!(p.parse_line("").is_none());
        assert!(p.parse_line(" \t").is_none());
        let ev = p
            .parse_line("nginx: [emerg] unknown directive \"foo\" in /etc/nginx/nginx.conf:10")
            .expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "nginx");
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::NGINX_ERROR,
                LogSourceTag::NGINX_ERROR_CANONICAL
            ]
        );
        assert_eq!(keys(&ev), vec!["message"]);
        assert_eq!(
            ev.field_str("message"),
            Some("nginx: [emerg] unknown directive \"foo\" in /etc/nginx/nginx.conf:10")
        );
        let first = p.parse_line(NOTICE).expect("event");
        let ev = p
            .parse_line("second line of a multi-line message")
            .expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert!(!ev.tz_explicit);
        // a continuation that carries a PHP message is tagged
        let ev = p
            .parse_line("PHP message: PHP Warning:  b in /x.php on line 2\" while reading response header from upstream")
            .expect("event");
        assert!(ev.timestamp_inferred);
        assert!(ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
    }

    #[test]
    fn malformed_numbers_do_not_panic() {
        let ev =
            parse("2026/10/26 11:00:00 [notice] 99999999999999999999#1: *99999999999999999999 x");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
        assert_eq!(ev.field("tid"), Some(&FieldValue::Int(1)));
        assert_eq!(ev.field("connection"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("message"), Some("x"));
        // impossible date: fields kept, timestamp borrowed
        let mut p = NginxErrorParser::new(ctx("error.log"));
        let first = p.parse_line(NOTICE).expect("event");
        let ev = p
            .parse_line("2026/13/40 25:61:61 [notice] 1#1: bad date")
            .expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.field_str("message"), Some("bad date"));
        let ev = NginxErrorParser::new(ctx("error.log"))
            .parse_line("2026/13/40 25:61:61 [notice] 1#1: bad date, no previous entry")
            .expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
    }

    #[test]
    fn timezone_assumptions_apply_to_the_naive_time() {
        let utc = ParseContext::new(
            Path::new("error.log"),
            TzAssumption::Fixed(FixedOffset::east_opt(0).expect("utc")),
        );
        let ev = NginxErrorParser::new(utc)
            .parse_line(NOTICE)
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00+00:00");
        let tokyo = ParseContext::new(
            Path::new("error.log"),
            TzAssumption::Named(chrono_tz::Asia::Tokyo),
        );
        let ev = NginxErrorParser::new(tokyo)
            .parse_line(NOTICE)
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00+09:00");
        assert!(!ev.tz_explicit);
    }

    #[test]
    fn dst_ambiguity_is_reported_once_per_file() {
        crate::errorlog::set_quiet(true);
        let berlin = ParseContext::new(
            Path::new("error.log"),
            TzAssumption::Named(chrono_tz::Europe::Berlin),
        );
        let mut p = NginxErrorParser::new(berlin);
        let ev = p
            .parse_line("2026/10/25 02:30:00 [notice] 1#1: ambiguous")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-25T02:30:00+02:00");
        assert!(p.dst_warned);
    }

    #[test]
    fn context_tags_and_hostname_are_applied() {
        let mut c = ctx("error.log");
        c.extra_tags = vec![LogSourceTag::WEBSERVER];
        c.hostname_hint = Some("web01".to_string());
        let mut p = NginxErrorParser::new(c);
        let ev = p.parse_line(NOTICE).expect("event");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert!(ev.tags.contains(&LogSourceTag::WEBSERVER));
        let ev = p.parse_line("continuation").expect("event");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert!(ev.tags.contains(&LogSourceTag::WEBSERVER));
    }

    #[test]
    fn web_fixture_parses_every_line() {
        let lines = fixture("test_files/web/nginx/error.log");
        assert_eq!(lines.len(), 5);
        let mut p = NginxErrorParser::new(ctx("test_files/web/nginx/error.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 5);
        assert!(
            events
                .iter()
                .all(|e| !e.timestamp_inferred && !e.tz_explicit)
        );
        assert!(events.iter().all(|e| e.tags[0] == LogSourceTag::NGINX_ERROR
            && e.tags[1] == LogSourceTag::NGINX_ERROR_CANONICAL));
        assert!(
            events
                .iter()
                .all(|e| !e.tags.contains(&LogSourceTag::PHP_ERROR_LOG))
        );
        assert_eq!(events[1].field_str("message"), Some("nginx/1.26.3"));
        assert_eq!(events[2].field_str("client"), Some("203.0.113.10"));
        assert_eq!(
            events[3].field_str("message"),
            Some("worker process 2001 exited on signal 6 (core dumped)")
        );
        assert_eq!(events[4].field_str("referrer"), Some("http://example.com/"));
        assert_eq!(rfc(&events[0]), "2026-10-26T11:00:00+09:00");
        assert_eq!(rfc(&events[4]), "2026-10-26T11:02:00+09:00");
    }

    #[test]
    fn php2shell_fpm_fixture_parses_every_line() {
        let lines = fixture("test_files/php2shell-fpm/nginx/error.log");
        assert_eq!(lines.len(), 3);
        let mut p = NginxErrorParser::new(ctx("test_files/php2shell-fpm/nginx/error.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|e| e.field_str("client") == Some("198.51.100.99"))
        );
        assert!(
            events
                .iter()
                .all(|e| e.field("connection") == Some(&FieldValue::Int(15)))
        );
        assert_eq!(
            events[0].field_str("message"),
            Some(
                "recv() failed (104: Connection reset by peer) while reading response header from upstream"
            )
        );
        assert_eq!(events[0].field_str("host"), Some("203.0.113.30"));
        assert!(!events[0].tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert!(!events[1].tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert!(events[2].tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(events[2].field_str("php_type"), Some("Fatal error"));
        assert_eq!(
            events[2].field_str("host"),
            Some("203.0.113.30, evil.example")
        );
        assert_eq!(
            events[2].field_str("request"),
            Some("POST /index.php?a=1,b=2 HTTP/1.1")
        );
    }

    #[test]
    fn sniffing_recognizes_nginx_error_logs() {
        let web = fixture("test_files/web/nginx/error.log");
        assert_eq!(
            sniff_format(
                &web,
                &path_hints(Path::new("test_files/web/nginx/error.log"))
            ),
            Some(LogFormat::NginxError)
        );
        assert_eq!(
            sniff_format(&web, &PathHints::default()),
            Some(LogFormat::NginxError)
        );
        let fpm = fixture("test_files/php2shell-fpm/nginx/error.log");
        assert_eq!(
            sniff_format(&fpm, &PathHints::default()),
            Some(LogFormat::NginxError)
        );
    }
}
