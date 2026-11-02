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

//! PHP error log and php-fpm log parsers, plus the PHP-message detector every other parser uses
//! (amendment A3). See design §4.6, §4.7 and amendments A3, A7, A9.
//!
//! Shapes:
//! - PHP error log (`error_log` ini setting):
//!   `[24-Oct-2026 15:35:33 UTC] PHP Fatal error:  Allowed memory size ... in Unknown on line 0`.
//!   The zone token is optional (`UTC`, `Europe/Berlin`, `+09:00`; an unknown token such as `JST`
//!   falls back to `-z` with one warning per file), as is the `PHP <type>:` prefix (user
//!   `error_log()` lines such as `WordPress database error ...`). Stack-trace lines
//!   (`Stack trace:`, `#0 {main}`, `  thrown in ...`) are continuations of the previous entry.
//! - php-fpm master log: `[26-Oct-2026 11:01:00] WARNING: [pool www] child 2010 said into stderr: "..."`
//!   and `[26-Oct-2026 11:00:00.123456] DEBUG: pid 1, ...` (fraction only at debug level). A PHP
//!   error-log line inside the fpm log (php-fpm and PHP sharing one `error_log`) keeps its own
//!   timestamp and gets the PHP fields.
//!
//! [`detect_php_message`] finds a PHP engine message inside any text: at its start (mod_php
//! `[:error]`/`[php:error]` lines, syslog `php[1234]: PHP ...`), after a `PHP message: ` prefix
//! (Apache `proxy_fcgi` `Got error 'PHP message: ...'`, nginx `FastCGI sent in stderr: "PHP message:
//! ..."`) or after an opening quote (php-fpm `said into stderr: "PHP Warning:  ..."`).

use super::timestamp::{self, Resolution, TzAssumption};
use super::{LineParser, ParseContext, continuation_event};
use crate::errorlog::log_warn;
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use regex::{Captures, Regex};
use std::sync::LazyLock;

/// The message types the PHP engine writes after `PHP ` (`PHP Fatal error:  ...`).
const PHP_TYPES: &str = "Fatal error|Warning|Notice|Deprecated|Parse error|Strict Standards|\
                         Recoverable fatal error|Core Warning|Core Error|Compile Error|\
                         Compile Warning|User Error|User Warning|User Notice|User Deprecated|\
                         Stack trace";

/// Amendment A3. The optional prefix (`...PHP message: `, or the quote that opens the message after
/// proxy_fcgi's `Got error '` / php-fpm's `said into stderr: "` / nginx's `sent in stderr: "`)
/// is lazy (`??`) so that
/// a text starting with `PHP <type>:` is taken as it is and never skipped in favour of a quoted PHP
/// message further right. One or two spaces follow the colon (`PHP Stack trace:` may end the text).
static PHP_MESSAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"^(?P<prefix>.*?(?:PHP message: |Got error '|said into stderr: "|sent in stderr: "))??PHP (?P<type>{PHP_TYPES}):(?:\s{{1,2}}|$)(?P<text>.*)$"#
    ))
    .expect("static regex")
});

/// Trailing ` in <file> on line <n>` or ` in <file>:<n>`; the greedy head picks the last ` in `.
static PHP_LOCATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^.* in (?P<file>.+?)(?: on line |:)(?P<line>\d+)$").expect("static regex")
});

/// Amendment A9: the PHP error log entry.
static PHP_ERROR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\[(?P<time>\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2})(?: (?P<zone>[A-Za-z][\w/+\-]*|[+-]\d{2}:?\d{2}))?\] (?P<msg>.*)$",
    )
    .expect("static regex")
});

/// php-fpm's zlog levels; a `[date] LEVEL: ` line is an FPM entry, never a PHP error log entry.
static FPM_LEVEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<level>DEBUG|NOTICE|WARNING|ERROR|ALERT): (?P<rest>.*)$")
        .expect("static regex")
});

/// The php-fpm master log entry (`[26-Oct-2026 11:00:00.123456]` at debug level).
static FPM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\[(?P<time>\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2})(?P<frac>\.\d{1,9})?\] (?P<level>DEBUG|NOTICE|WARNING|ERROR|ALERT): (?P<rest>.*)$",
    )
    .expect("static regex")
});

static FPM_POOL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[pool (?P<pool>[^\]]+)\](?: (?P<rest>.*))?$").expect("static regex")
});

static FPM_CHILD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bchild (?P<pid>\d+)\b").expect("static regex"));

/// A PHP message found inside a log line (`PHP Fatal error:  ... in <file> on line <n>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhpMessage {
    pub php_type: String,
    /// Everything after `PHP <type>: `, including the ` in <file> on line <n>` suffix.
    pub text: String,
    pub file: Option<String>,
    pub line: Option<i64>,
}

/// Detect a PHP engine message anywhere in `message` (`PHP Warning:  ...`, `PHP message: PHP
/// Fatal error:  ...`). Used by the Apache/nginx/php-fpm/syslog parsers to add the
/// `php/error_log` tag and the `php_type`/`php_message`/`file`/`line` fields.
pub fn detect_php_message(message: &str) -> Option<PhpMessage> {
    let caps = PHP_MESSAGE_RE.captures(message)?;
    let php_type = caps.name("type")?.as_str().to_string();
    let prefix = caps.name("prefix").map_or("", |m| m.as_str());
    let mut text = caps.name("text").map_or("", |m| m.as_str());
    // The wrapper quoted the PHP text (`Got error 'PHP message: ...'`, `said into stderr: "PHP
    // ..."`, `FastCGI sent in stderr: "PHP message: ..." while reading ...`): stop at the closing
    // quote so that the wrapper's own trailing text is not taken for part of the PHP message.
    if let Some(quote) = wrapping_quote(prefix)
        && let Some(idx) = text.rfind(quote)
    {
        text = &text[..idx];
    }
    // nginx concatenates several `PHP message: ` items into one quoted string: keep the first.
    if let Some(idx) = text.find("PHP message: ")
        && idx > 0
    {
        text = &text[..idx];
    }
    let text = text.trim();
    let (file, line) = split_location(text);
    Some(PhpMessage {
        php_type,
        text: text.to_string(),
        file,
        line,
    })
}

/// The quote character that opened the PHP text, when the prefix ends with one (directly, or right
/// before `PHP message: `).
fn wrapping_quote(prefix: &str) -> Option<char> {
    let before = prefix.strip_suffix("PHP message: ").unwrap_or(prefix);
    before.chars().last().filter(|c| matches!(c, '"' | '\''))
}

/// `file` and `line` from a trailing ` in <file> on line <n>` or ` in <file>:<n>`, after removing
/// one trailing single or double quote (proxy_fcgi wraps the PHP message in quotes).
pub fn split_location(text: &str) -> (Option<String>, Option<i64>) {
    // Wrappers end the message with a quote; proxy_fcgi joins several messages with a literal
    // `\n`, nginx with `; `.
    let mut t = text.trim_end();
    loop {
        let next = t
            .strip_suffix(['"', '\''])
            .or_else(|| t.strip_suffix("\\n"))
            .or_else(|| t.strip_suffix(';'))
            .map(str::trim_end);
        match next {
            Some(n) if n.len() < t.len() => t = n,
            _ => break,
        }
    }
    match PHP_LOCATION_RE.captures(t) {
        Some(c) => (
            c.name("file").map(|m| m.as_str().to_string()),
            c.name("line").and_then(|m| m.as_str().parse::<i64>().ok()),
        ),
        None => (None, None),
    }
}

/// Add the PHP tag and fields to `ev` when `message` carries a PHP engine message.
pub fn tag_php_message(ev: &mut ParsedEvent, message: &str) {
    if let Some(php) = detect_php_message(message) {
        ev.add_tag(LogSourceTag::PHP_ERROR_LOG);
        ev.push("php_type", php.php_type);
        ev.push("php_message", php.text);
        ev.push("file", php.file);
        ev.push("line", php.line);
    }
}

/// Interpret a naive timestamp in `tz`; an ambiguous or non-existent local time (DST change) is
/// recorded in the error log once per file (amendment A7). Shared by the web-server error log
/// parsers, which have no zone information either.
pub(crate) fn resolve_naive_logged(
    naive: NaiveDateTime,
    tz: &TzAssumption,
    file: &str,
    warned: &mut bool,
) -> DateTime<FixedOffset> {
    let (dt, res) = timestamp::resolve_naive(naive, tz);
    if res != Resolution::Exact && !*warned {
        *warned = true;
        let what = match res {
            Resolution::Ambiguous => {
                "is ambiguous (clocks went back); the earlier instant was used"
            }
            _ => "does not exist (clocks went forward); one hour was added",
        };
        log_warn(&format!(
            "{file}: the local time {naive} {what} in timezone {tz}. Reported once per file."
        ));
    }
    dt
}

/// `26-Oct-2026 11:01:00` (+ optional `.123456` fraction) → naive date-time.
fn parse_php_time(date_time: &str, frac: Option<&str>) -> Option<NaiveDateTime> {
    let (date, clock) = date_time.split_once(' ')?;
    let mut d = date.split('-');
    let day: u32 = d.next()?.parse().ok()?;
    let month = timestamp::month_from_abbr(d.next()?)?;
    let year: i32 = d.next()?.parse().ok()?;
    let mut t = clock.split(':');
    let h: u32 = t.next()?.parse().ok()?;
    let m: u32 = t.next()?.parse().ok()?;
    let s: u32 = t.next()?.parse().ok()?;
    let nanos = frac.map_or(0, timestamp::frac_to_nanos);
    timestamp::naive_from_parts(year, month, day, h, m, s, nanos)
}

/// The text after an fpm level: `[pool www] child 2010 said into stderr: "..."` → the pool, the
/// child pid (`child N`) and the message.
fn split_fpm_rest(rest: &str) -> (Option<&str>, FieldValue, &str) {
    let (pool, message) = match FPM_POOL_RE.captures(rest) {
        Some(c) => (
            c.name("pool").map(|m| m.as_str()),
            c.name("rest").map_or("", |m| m.as_str()),
        ),
        None => (None, rest),
    };
    let child_pid = FPM_CHILD_RE
        .captures(message)
        .and_then(|c| c.name("pid"))
        .map_or(FieldValue::Null, |m| FieldValue::int_or_null(m.as_str()));
    (pool, child_pid, message)
}

/// Whether `line` starts a PHP error log record. A php-fpm line (`] NOTICE: `, `] WARNING: `, ...)
/// has the same date header but is not one.
pub fn matches_error_entry(line: &str) -> bool {
    PHP_ERROR_RE
        .captures(line)
        .is_some_and(|c| !FPM_LEVEL_RE.is_match(c.name("msg").map_or("", |m| m.as_str())))
}

/// Whether `line` starts a php-fpm master log record.
pub fn matches_fpm_entry(line: &str) -> bool {
    FPM_RE.is_match(line)
}

/// Resolve a PHP error-log header time (amendments A7 and A9): a zone token that parses (`UTC`,
/// `Europe/Berlin`, `+09:00`) is used as written and the result is explicit; an unknown token
/// (`JST`) falls back to `-z` with one warning per file; no token means `-z` silently.
fn resolve_php_time(
    naive: NaiveDateTime,
    zone: Option<&str>,
    ctx: &ParseContext,
    zone_warned: &mut bool,
    dst_warned: &mut bool,
) -> (DateTime<FixedOffset>, bool) {
    if let Some(token) = zone {
        if let Some(tz) = timestamp::parse_zone_token(token) {
            return (
                resolve_naive_logged(naive, &tz, &ctx.display_name, dst_warned),
                true,
            );
        }
        if !*zone_warned {
            *zone_warned = true;
            log_warn(&format!(
                "{}: unknown timezone '{token}' in a PHP error log timestamp; such timestamps are read as {} (see -z). Reported once per file.",
                ctx.display_name, ctx.tz
            ));
        }
    }
    (
        resolve_naive_logged(naive, &ctx.tz, &ctx.display_name, dst_warned),
        false,
    )
}

pub struct PhpErrorParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
    /// An unknown zone token (`JST`) has already been reported for this file.
    zone_warned: bool,
    /// A DST ambiguity has already been reported for this file.
    dst_warned: bool,
}

impl PhpErrorParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self {
            ctx,
            last_ts: None,
            zone_warned: false,
            dst_warned: false,
        }
    }

    /// The instant of an entry and whether the line carried a usable zone of its own.
    fn resolve(
        &mut self,
        naive: NaiveDateTime,
        zone: Option<&str>,
    ) -> (DateTime<FixedOffset>, bool) {
        resolve_php_time(
            naive,
            zone,
            &self.ctx,
            &mut self.zone_warned,
            &mut self.dst_warned,
        )
    }
}

impl LineParser for PhpErrorParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let Some(caps) = PHP_ERROR_RE.captures(line) else {
            // `Stack trace:`, `#0 {main}`, `  thrown in ...`, or CLI-style `PHP Warning:  ...`
            // lines without a date.
            let mut ev = continuation_event(line, &LogSourceTag::PHP_ERROR_LOG, &[], self.last_ts);
            tag_php_message(&mut ev, line.trim_end());
            self.ctx.finish(&mut ev);
            return Some(ev);
        };
        let time = caps.name("time").map_or("", |m| m.as_str());
        let zone = caps.name("zone").map(|m| m.as_str());
        let msg = caps.name("msg").map_or("", |m| m.as_str()).trim_end();

        let mut ev = ParsedEvent::new(line, &LogSourceTag::PHP_ERROR_LOG);
        match parse_php_time(time, None) {
            Some(naive) => {
                let (ts, explicit) = self.resolve(naive, zone);
                ev.timestamp = Some(ts);
                ev.tz_explicit = explicit;
                self.last_ts = Some(ts);
            }
            None => {
                // The header matched but the date is impossible (e.g. day 32): keep the fields,
                // place the line like a continuation.
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }
        // `file`/`line` are the PHP script location PHP reports at the end of the message
        // (`in /var/www/x.php on line 3`, `in Unknown on line 0` before any script ran). They
        // repeat the end of `message` and are easily mistaken for the log location, so they are
        // extra fields rather than details.
        let (php_type, message, file, line) = match detect_php_message(msg) {
            Some(php) => (FieldValue::from(php.php_type), php.text, php.file, php.line),
            None => {
                // A user `error_log()` line (or a php-fpm line inside a PHP error log).
                let (file, line) = split_location(msg);
                (FieldValue::Null, msg.to_string(), file, line)
            }
        };
        ev.push("php_type", php_type);
        ev.push("message", message);
        ev.push("file", file);
        ev.push("line", line);
        ev.push("zone", zone);
        // php-fpm's master log sharing the file (`[date] NOTICE: [pool www] child 1 started`):
        // the line is an fpm event too, with the fpm fields as extra fields.
        if let Some(c) = FPM_LEVEL_RE.captures(msg) {
            let (pool, child_pid, _) = split_fpm_rest(c.name("rest").map_or("", |m| m.as_str()));
            ev.add_tag(LogSourceTag::PHP_FPM);
            ev.push("level", c.name("level").map_or("", |m| m.as_str()));
            ev.push("pool", pool);
            ev.push("child_pid", child_pid);
        }
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}

pub struct PhpFpmParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
    /// An unknown zone token in a PHP error-log line has already been reported for this file.
    zone_warned: bool,
    /// A DST ambiguity has already been reported for this file.
    dst_warned: bool,
}

impl PhpFpmParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self {
            ctx,
            last_ts: None,
            zone_warned: false,
            dst_warned: false,
        }
    }

    /// A PHP error-log entry (`[26-Oct-2026 11:07:00 UTC] PHP Warning:  ...`) inside the fpm log:
    /// php-fpm's own `error_log` and PHP's `error_log` ini setting may point at the same file. The
    /// line keeps its own timestamp and zone, gets the fpm field shape (no level, pool or child)
    /// and the PHP fields.
    fn php_error_entry(&mut self, line: &str, caps: &Captures<'_>) -> ParsedEvent {
        let time = caps.name("time").map_or("", |m| m.as_str());
        let zone = caps.name("zone").map(|m| m.as_str());
        let msg = caps.name("msg").map_or("", |m| m.as_str()).trim_end();
        let mut ev = ParsedEvent::new(line, &LogSourceTag::PHP_FPM);
        match parse_php_time(time, None) {
            Some(naive) => {
                let (ts, explicit) = resolve_php_time(
                    naive,
                    zone,
                    &self.ctx,
                    &mut self.zone_warned,
                    &mut self.dst_warned,
                );
                ev.timestamp = Some(ts);
                ev.tz_explicit = explicit;
                self.last_ts = Some(ts);
            }
            None => {
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }
        ev.push("level", FieldValue::Null);
        ev.push("pool", FieldValue::Null);
        ev.push("child_pid", FieldValue::Null);
        ev.push("message", msg);
        ev.push("zone", zone);
        tag_php_message(&mut ev, msg);
        self.ctx.finish(&mut ev);
        ev
    }
}

impl LineParser for PhpFpmParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let Some(caps) = FPM_RE.captures(line) else {
            if let Some(c) = PHP_ERROR_RE.captures(line) {
                return Some(self.php_error_entry(line, &c));
            }
            let mut ev = continuation_event(line, &LogSourceTag::PHP_FPM, &[], self.last_ts);
            tag_php_message(&mut ev, line.trim_end());
            self.ctx.finish(&mut ev);
            return Some(ev);
        };
        let time = caps.name("time").map_or("", |m| m.as_str());
        let frac = caps.name("frac").map(|m| m.as_str());
        let level = caps.name("level").map_or("", |m| m.as_str());
        let rest = caps.name("rest").map_or("", |m| m.as_str()).trim_end();

        let mut ev = ParsedEvent::new(line, &LogSourceTag::PHP_FPM);
        match parse_php_time(time, frac) {
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
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }
        // `[pool www] child 2010 said into stderr: "..."`: the pool is its own field, the message
        // is the rest.
        let (pool, child_pid, message) = split_fpm_rest(rest);
        ev.push("level", level);
        ev.push("pool", pool);
        ev.push("child_pid", child_pid);
        ev.push("message", message);
        tag_php_message(&mut ev, message);
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{LogFormat, PathHints, path_hints, sniff_format};
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

    const HONEYPOT: &str = "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0";

    // ----- detect_php_message -------------------------------------------------------------

    #[test]
    fn detects_the_honeypot_shape() {
        let php = detect_php_message(HONEYPOT).expect("php message");
        assert_eq!(php.php_type, "Fatal error");
        assert_eq!(
            php.text,
            "Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"
        );
        assert_eq!(php.file.as_deref(), Some("Unknown"));
        assert_eq!(php.line, Some(0));
    }

    #[test]
    fn detects_every_type_with_one_or_two_spaces() {
        for t in [
            "Fatal error",
            "Warning",
            "Notice",
            "Deprecated",
            "Parse error",
            "Strict Standards",
            "Recoverable fatal error",
            "Core Warning",
            "Core Error",
            "Compile Error",
            "Compile Warning",
            "User Error",
            "User Warning",
            "User Notice",
            "User Deprecated",
            "Stack trace",
        ] {
            let two = detect_php_message(&format!("PHP {t}:  x in /a.php on line 7")).expect(t);
            assert_eq!(two.php_type, t);
            assert_eq!(two.text, "x in /a.php on line 7");
            assert_eq!(two.file.as_deref(), Some("/a.php"));
            assert_eq!(two.line, Some(7));
            let one = detect_php_message(&format!("PHP {t}: y")).expect(t);
            assert_eq!(one.php_type, t);
            assert_eq!(one.text, "y");
            assert_eq!(one.file, None);
            assert_eq!(one.line, None);
        }
        // `PHP Stack trace:` ends the text in xdebug output
        let st = detect_php_message("PHP Stack trace:").expect("stack trace");
        assert_eq!(st.php_type, "Stack trace");
        assert_eq!(st.text, "");
    }

    #[test]
    fn rejects_non_php_text() {
        assert_eq!(detect_php_message("sh: 1: wget: not found"), None);
        assert_eq!(
            detect_php_message("PHP Warning:foo"),
            None,
            "colon needs a space"
        );
        assert_eq!(detect_php_message("PHP Unknown:  foo"), None);
        assert_eq!(
            detect_php_message("php warning:  foo"),
            None,
            "case matters"
        );
        assert_eq!(
            detect_php_message("AH00051: child pid 31 exit signal Segmentation fault (11)"),
            None
        );
        assert_eq!(detect_php_message(""), None);
        assert_eq!(
            detect_php_message("PHP message: user error_log() text without a type"),
            None
        );
    }

    #[test]
    fn php_message_prefix_from_proxy_fcgi_is_unwrapped() {
        let msg = "AH01071: Got error 'PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0'";
        let php = detect_php_message(msg).expect("php");
        assert_eq!(php.php_type, "Fatal error");
        assert_eq!(
            php.text,
            "Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0"
        );
        assert_eq!(php.file.as_deref(), Some("Unknown"));
        assert_eq!(php.line, Some(0));
        // the quote inside the PHP text is not mistaken for the closing one
        let msg = "AH01071: Got error 'PHP message: PHP Warning:  Table 'wp.wp_options' doesn't exist in /var/www/html/wp.php on line 3'";
        let php = detect_php_message(msg).expect("php");
        assert_eq!(
            php.text,
            "Table 'wp.wp_options' doesn't exist in /var/www/html/wp.php on line 3"
        );
        assert_eq!(php.file.as_deref(), Some("/var/www/html/wp.php"));
        assert_eq!(php.line, Some(3));
    }

    #[test]
    fn nginx_fastcgi_stderr_is_found_inside_the_quotes() {
        let msg = "FastCGI sent in stderr: \"PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0\" while reading response header from upstream";
        let php = detect_php_message(msg).expect("php");
        assert_eq!(php.php_type, "Fatal error");
        assert_eq!(
            php.text,
            "Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"
        );
        assert_eq!(php.file.as_deref(), Some("Unknown"));
        assert_eq!(php.line, Some(0));
        // a PHP text with its own double quotes
        let msg = "FastCGI sent in stderr: \"PHP message: PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0\" while reading response header from upstream";
        let php = detect_php_message(msg).expect("php");
        assert_eq!(php.php_type, "Warning");
        assert!(
            php.text
                .ends_with("\",\" characters are allowed in Unknown on line 0"),
            "{}",
            php.text
        );
        assert_eq!(php.file.as_deref(), Some("Unknown"));
        assert_eq!(php.line, Some(0));
        // several concatenated PHP messages: the first one is reported
        let msg = "FastCGI sent in stderr: \"PHP message: PHP Warning:  a in /x.php on line 1PHP message: PHP Notice:  b in /x.php on line 2\" while reading response header from upstream";
        let php = detect_php_message(msg).expect("php");
        assert_eq!(php.php_type, "Warning");
        assert_eq!(php.text, "a in /x.php on line 1");
        assert_eq!(php.line, Some(1));
    }

    #[test]
    fn fpm_stderr_quote_is_a_valid_prefix() {
        let msg = "child 2012 said into stderr: \"PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0\"";
        let php = detect_php_message(msg).expect("php");
        assert_eq!(php.php_type, "Warning");
        assert_eq!(
            php.text,
            "PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0"
        );
        assert_eq!(php.file.as_deref(), Some("Unknown"));
        assert_eq!(php.line, Some(0));
        // shell output is not a PHP message
        assert_eq!(
            detect_php_message("child 2010 said into stderr: \"sh: 1: wget: not found\""),
            None
        );
    }

    #[test]
    fn leading_php_message_wins_over_a_quoted_one() {
        let php = detect_php_message("PHP Warning:  foo \"PHP Notice: bar\" in /x.php on line 1")
            .expect("php");
        assert_eq!(php.php_type, "Warning");
        assert_eq!(php.text, "foo \"PHP Notice: bar\" in /x.php on line 1");
        assert_eq!(php.file.as_deref(), Some("/x.php"));
    }

    #[test]
    fn file_and_line_shapes() {
        let php = detect_php_message(
            "PHP Fatal error:  Uncaught Exception: boom in /var/www/html/x.php:3",
        )
        .expect("php");
        assert_eq!(
            php.text,
            "Uncaught Exception: boom in /var/www/html/x.php:3"
        );
        assert_eq!(php.file.as_deref(), Some("/var/www/html/x.php"));
        assert_eq!(php.line, Some(3));
        // the last ` in ` wins, not one inside the message
        let php = detect_php_message(
            "PHP Warning:  file_get_contents(http://162.35.99.94:8080/pwn-198.51.100.1): Failed to open stream: Connection timed out in Command line code on line 1",
        )
        .expect("php");
        assert_eq!(php.file.as_deref(), Some("Command line code"));
        assert_eq!(php.line, Some(1));
        // a trailing quote is stripped for the location but kept in the text
        let php = detect_php_message("PHP Warning:  foo in /x.php on line 3'").expect("php");
        assert_eq!(php.text, "foo in /x.php on line 3'");
        assert_eq!(php.file.as_deref(), Some("/x.php"));
        assert_eq!(php.line, Some(3));
        // no location, or text after the location: nothing extracted
        assert_eq!(split_location("foo in bar"), (None, None));
        assert_eq!(
            split_location("foo in /x.php on line 3 (extra)"),
            (None, None)
        );
        // a line number that overflows i64 does not panic
        let (file, line) = split_location("x in /x.php on line 99999999999999999999");
        assert_eq!(file.as_deref(), Some("/x.php"));
        assert_eq!(line, None);
        // windows paths keep their drive colon
        let (file, line) = split_location(r"x in C:\www\x.php on line 12");
        assert_eq!(file.as_deref(), Some(r"C:\www\x.php"));
        assert_eq!(line, Some(12));
    }

    #[test]
    fn tag_php_message_adds_tag_and_fields_after_the_details() {
        let mut ev = ParsedEvent::new("raw", &LogSourceTag::APACHE_ERROR);
        ev.push("message", HONEYPOT);
        tag_php_message(&mut ev, HONEYPOT);
        assert!(ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG));
        assert_eq!(ev.field_str("php_type"), Some("Fatal error"));
        assert_eq!(
            ev.field_str("php_message"),
            Some(
                "Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"
            )
        );
        assert_eq!(ev.field_str("file"), Some("Unknown"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(0)));
        let mut plain = ParsedEvent::new("raw", &LogSourceTag::APACHE_ERROR);
        tag_php_message(&mut plain, "sh: 1: wget: not found");
        assert_eq!(plain.tags, vec![LogSourceTag::APACHE_ERROR]);
        assert!(plain.fields.is_empty());
    }

    // ----- entry detection ---------------------------------------------------------------

    #[test]
    fn error_and_fpm_entries_are_told_apart() {
        for l in [
            "[24-Oct-2026 15:35:33 UTC] PHP Fatal error:  x",
            "[26-Oct-2026 11:00:59 Europe/Berlin] PHP Warning:  x",
            "[26-Oct-2026 11:08:00 +09:00] PHP Fatal error:  x",
            "[26-Oct-2026 11:08:00 +0900] PHP Fatal error:  x",
            "[26-Oct-2026 11:08:00 -05:00] PHP Fatal error:  x",
            "[26-Oct-2026 11:07:00] PHP Warning:  foo in /var/www/html/x.php on line 3",
            "[26-Oct-2026 11:06:00 Europe/Berlin] WordPress database error Table 'wp.wp_options' doesn't exist",
            "[26-Oct-2026 11:06:00] some text",
            "[26-Oct-2026 11:06:00 JST] PHP Notice:  x",
            "[26-Oct-2026 11:06:00 America/Argentina/Buenos_Aires] PHP Notice:  x",
            "[26-Oct-2026 11:00:00] notice: lowercase is not an fpm level",
        ] {
            assert!(matches_error_entry(l), "error entry: {l}");
            assert!(!matches_fpm_entry(l), "not fpm: {l}");
        }
        for l in [
            "[26-Oct-2026 11:00:00] NOTICE: fpm is running, pid 1",
            "[26-Oct-2026 11:00:00] WARNING: [pool www] child 2010 said into stderr: \"sh: 1: wget: not found\"",
            "[26-Oct-2026 11:00:00] ERROR: unable to bind listening socket",
            "[26-Oct-2026 11:00:00] ALERT: [pool www] user has not been defined",
            "[26-Oct-2026 11:00:00.123456] DEBUG: pid 1, fpm_event_loop(), line 419: event module is epoll",
            "[26-Oct-2026 11:00:00.123] NOTICE: fpm is running, pid 1",
        ] {
            assert!(matches_fpm_entry(l), "fpm entry: {l}");
            assert!(!matches_error_entry(l), "not error entry: {l}");
        }
        for l in [
            "",
            "Stack trace:",
            "#0 {main}",
            "  thrown in /var/www/html/x.php on line 3",
            "PHP Warning:  no date",
            "[26-Oct-2026 11:00:00]PHP Warning: no space",
            "[2026-10-26 11:00:00] PHP Warning:  iso date",
            "sh: 1: wget: not found",
        ] {
            assert!(!matches_error_entry(l), "not an entry: {l}");
            assert!(!matches_fpm_entry(l), "not an entry: {l}");
        }
    }

    #[test]
    fn sniffing_picks_the_right_php_format() {
        let err = fixture("test_files/php2shell-fpm/php-error.log");
        let fpm = fixture("test_files/php2shell-fpm/php8.3-fpm.log");
        assert_eq!(
            sniff_format(
                &err,
                &path_hints(Path::new("test_files/php2shell-fpm/php-error.log"))
            ),
            Some(LogFormat::PhpError)
        );
        assert_eq!(
            sniff_format(&err, &PathHints::default()),
            Some(LogFormat::PhpError)
        );
        assert_eq!(
            sniff_format(
                &fpm,
                &path_hints(Path::new("test_files/php2shell-fpm/php8.3-fpm.log"))
            ),
            Some(LogFormat::PhpFpm)
        );
        assert_eq!(
            sniff_format(&fpm, &PathHints::default()),
            Some(LogFormat::PhpFpm)
        );
        let utc = fixture("test_files/php2shell/php-error.log");
        assert_eq!(
            sniff_format(&utc, &PathHints::default()),
            Some(LogFormat::PhpError)
        );
    }

    // ----- PhpErrorParser ----------------------------------------------------------------

    #[test]
    fn utc_zone_token_is_explicit() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let ev = p
            .parse_line(&format!("[24-Oct-2026 15:35:33 UTC] {HONEYPOT}"))
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-24T15:35:33+00:00");
        assert!(ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "php/error_log");
        assert_eq!(ev.tags, vec![LogSourceTag::PHP_ERROR_LOG]);
        assert_eq!(
            keys(&ev),
            vec!["php_type", "message", "file", "line", "zone"]
        );
        assert_eq!(ev.field_str("php_type"), Some("Fatal error"));
        assert_eq!(
            ev.field_str("message"),
            Some(
                "Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"
            )
        );
        assert_eq!(ev.field_str("file"), Some("Unknown"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(0)));
        assert_eq!(ev.field_str("zone"), Some("UTC"));
        assert_eq!(ev.raw, format!("[24-Oct-2026 15:35:33 UTC] {HONEYPOT}"));
        assert_eq!(ev.hostname, None);
    }

    #[test]
    fn iana_zone_token_resolves_with_dst_rules() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:00:59 Europe/Berlin] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:59+01:00");
        assert!(ev.tz_explicit);
        assert_eq!(ev.field_str("zone"), Some("Europe/Berlin"));
        // summer time
        let ev = p
            .parse_line("[26-Jul-2026 11:00:59 Europe/Berlin] PHP Notice:  x")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-07-26T11:00:59+02:00");
    }

    #[test]
    fn offset_zone_token_is_explicit() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:08:00 +09:00] PHP Fatal error:  Uncaught Exception: boom in /var/www/html/x.php:3")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:08:00+09:00");
        assert!(ev.tz_explicit);
        assert_eq!(ev.field_str("zone"), Some("+09:00"));
        assert_eq!(ev.field_str("php_type"), Some("Fatal error"));
        assert_eq!(
            ev.field_str("message"),
            Some("Uncaught Exception: boom in /var/www/html/x.php:3")
        );
        assert_eq!(ev.field_str("file"), Some("/var/www/html/x.php"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(3)));
        let ev = p
            .parse_line("[26-Oct-2026 11:08:00 -0500] PHP Notice:  x")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:08:00-05:00");
        assert!(ev.tz_explicit);
    }

    #[test]
    fn missing_zone_uses_the_assumed_timezone_silently() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:07:00] PHP Warning:  foo in /var/www/html/x.php on line 3")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:07:00+09:00");
        assert!(!ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.field("zone"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(
            ev.field_str("message"),
            Some("foo in /var/www/html/x.php on line 3")
        );
        assert_eq!(ev.field_str("file"), Some("/var/www/html/x.php"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(3)));
        assert!(!p.zone_warned);
    }

    #[test]
    fn unknown_zone_token_falls_back_with_one_warning_per_file() {
        crate::errorlog::set_quiet(true);
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        assert!(!p.zone_warned);
        let ev = p
            .parse_line("[26-Oct-2026 11:07:00 JST] PHP Notice:  x")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:07:00+09:00", "ctx.tz is +09:00");
        assert!(!ev.tz_explicit, "an unknown token is not an explicit zone");
        assert_eq!(ev.field_str("zone"), Some("JST"));
        assert!(p.zone_warned);
        let ev = p
            .parse_line("[26-Oct-2026 11:07:01 JST] PHP Notice:  y")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:07:01+09:00");
        assert!(p.zone_warned);
        // a known token on the same file is still explicit
        let ev = p
            .parse_line("[26-Oct-2026 11:07:02 UTC] PHP Notice:  z")
            .expect("event");
        assert!(ev.tz_explicit);
        assert_eq!(rfc(&ev), "2026-10-26T11:07:02+00:00");
    }

    #[test]
    fn dst_ambiguity_is_reported_once_per_file() {
        crate::errorlog::set_quiet(true);
        let berlin = ParseContext::new(
            Path::new("php-error.log"),
            TzAssumption::Named(chrono_tz::Europe::Berlin),
        );
        let mut p = PhpErrorParser::new(berlin);
        let ev = p
            .parse_line("[25-Oct-2026 02:30:00] PHP Notice:  x")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-25T02:30:00+02:00", "earliest instant");
        assert!(p.dst_warned);
        let ev = p
            .parse_line("[29-Mar-2026 02:30:00] PHP Notice:  gap")
            .expect("event");
        assert_eq!(
            rfc(&ev),
            "2026-03-29T03:30:00+02:00",
            "gap moves forward one hour"
        );
        let mut fresh = PhpErrorParser::new(ParseContext::new(
            Path::new("php-error.log"),
            TzAssumption::Named(chrono_tz::Europe::Berlin),
        ));
        fresh
            .parse_line("[25-Oct-2026 01:30:00] PHP Notice:  fine")
            .expect("event");
        assert!(!fresh.dst_warned);
    }

    #[test]
    fn user_error_log_line_has_null_type() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let line = "[26-Oct-2026 11:06:00 Europe/Berlin] WordPress database error Table 'wp.wp_options' doesn't exist for query SELECT option_value FROM wp_options WHERE option_name = 'siteurl' LIMIT 1 made by require('wp-blog-header.php')";
        let expected = line.split_once("] ").expect("header").1;
        let ev = p.parse_line(line).expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:06:00+01:00");
        assert_eq!(ev.field("php_type"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("message"), Some(expected));
        assert_eq!(ev.field("file"), Some(&FieldValue::Null));
        assert_eq!(ev.field("line"), Some(&FieldValue::Null));
        assert_eq!(ev.tags, vec![LogSourceTag::PHP_ERROR_LOG]);
        // a user line that ends with a location still gets file/line
        let ev = p
            .parse_line("[26-Oct-2026 11:06:01] custom failure in /srv/app.php on line 42")
            .expect("event");
        assert_eq!(ev.field("php_type"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("file"), Some("/srv/app.php"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(42)));
    }

    #[test]
    fn stack_trace_lines_are_continuations() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let first = p
            .parse_line("[26-Oct-2026 11:08:00 +09:00] PHP Fatal error:  Uncaught Exception: boom in /var/www/html/x.php:3")
            .expect("event");
        for l in [
            "Stack trace:",
            "#0 {main}",
            "  thrown in /var/www/html/x.php on line 3",
        ] {
            let ev = p.parse_line(l).expect("event");
            assert_eq!(ev.timestamp, first.timestamp, "{l}");
            assert!(ev.timestamp_inferred, "{l}");
            assert!(!ev.tz_explicit);
            assert_eq!(ev.field_str("message"), Some(l));
            assert_eq!(ev.tags, vec![LogSourceTag::PHP_ERROR_LOG]);
            assert_eq!(ev.primary_logsource, "php/error_log");
            assert_eq!(ev.field("php_type"), None);
        }
        // a CLI-style line without a date carries its PHP fields as extra fields
        let ev = p
            .parse_line("PHP Warning:  foo in /x.php on line 1")
            .expect("event");
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(ev.field_str("php_message"), Some("foo in /x.php on line 1"));
        assert_eq!(ev.field_str("file"), Some("/x.php"));
    }

    #[test]
    fn continuation_before_any_entry_has_no_timestamp() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let ev = p.parse_line("#0 {main}").expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert!(p.parse_line("").is_none());
        assert!(p.parse_line("   \t").is_none());
    }

    #[test]
    fn control_characters_in_the_message_do_not_break_parsing() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let line = "[26-Oct-2026 11:09:00 Europe/Berlin] PHP Warning:  file_get_contents(http://198.51.100.99:8080/\u{1b}]0;pwned\u{7}): Failed to open stream: Connection timed out in Command line code on line 1";
        let ev = p.parse_line(line).expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:09:00+01:00");
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        let msg = ev.field_str("message").expect("message");
        assert!(msg.contains('\u{1b}') && msg.contains('\u{7}'));
        assert_eq!(ev.field_str("file"), Some("Command line code"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(1)));
    }

    #[test]
    fn impossible_date_keeps_the_fields_and_borrows_the_timestamp() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let first = p
            .parse_line("[26-Oct-2026 11:00:00 UTC] PHP Notice:  a")
            .expect("event");
        let ev = p
            .parse_line("[32-Oct-2026 11:00:00 UTC] PHP Notice:  b")
            .expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.field_str("php_type"), Some("Notice"));
        assert_eq!(ev.field_str("message"), Some("b"));
        let ev = p
            .parse_line("[26-Xyz-2026 11:00:00] PHP Notice:  c")
            .expect("event");
        assert!(ev.timestamp_inferred);
        let ev = p
            .parse_line("[26-Oct-2026 25:00:00] PHP Notice:  d")
            .expect("event");
        assert!(ev.timestamp_inferred);
    }

    #[test]
    fn fpm_line_inside_a_php_error_log_is_still_an_entry() {
        let mut p = PhpErrorParser::new(ctx("php-error.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:00:00] NOTICE: fpm is running, pid 1")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00+09:00");
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "php/error_log");
        assert_eq!(
            ev.tags,
            vec![LogSourceTag::PHP_ERROR_LOG, LogSourceTag::PHP_FPM]
        );
        assert_eq!(ev.field("php_type"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("NOTICE: fpm is running, pid 1")
        );
        assert_eq!(
            keys(&ev),
            vec![
                "php_type",
                "message",
                "file",
                "line",
                "zone",
                "level",
                "pool",
                "child_pid"
            ]
        );
        assert_eq!(ev.field_str("level"), Some("NOTICE"));
        assert_eq!(ev.field("pool"), Some(&FieldValue::Null));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Null));
        let ev = p
            .parse_line("[26-Oct-2026 11:01:00] WARNING: [pool www] child 2010 said into stderr: \"sh: 1: wget: not found\"")
            .expect("event");
        assert!(ev.tags.contains(&LogSourceTag::PHP_FPM));
        assert_eq!(ev.field_str("level"), Some("WARNING"));
        assert_eq!(ev.field_str("pool"), Some("www"));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Int(2010)));
        assert_eq!(ev.field("php_type"), Some(&FieldValue::Null));
        // relayed PHP output is a PHP message first and an fpm line second
        let ev = p
            .parse_line("[26-Oct-2026 11:05:00] WARNING: [pool www] child 2012 said into stderr: \"PHP Warning:  foo in /x.php on line 3\"")
            .expect("event");
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(ev.field_str("message"), Some("foo in /x.php on line 3"));
        assert_eq!(ev.field_str("file"), Some("/x.php"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(3)));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Int(2012)));
        assert!(ev.tags.contains(&LogSourceTag::PHP_FPM));
        // a user error_log() line that merely starts with a capitalized word is not fpm output
        let ev = p
            .parse_line("[26-Oct-2026 11:06:00] Notice: lowercase is not an fpm level")
            .expect("event");
        assert_eq!(ev.tags, vec![LogSourceTag::PHP_ERROR_LOG]);
        assert_eq!(ev.field("level"), None);
    }

    #[test]
    fn context_tags_and_hostname_are_applied() {
        let mut c = ctx("php-error.log");
        c.extra_tags = vec![LogSourceTag::LINUX_SYSLOG];
        c.hostname_hint = Some("web01".to_string());
        let mut p = PhpErrorParser::new(c);
        let ev = p
            .parse_line("[26-Oct-2026 11:07:00] PHP Warning:  foo")
            .expect("event");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert!(ev.tags.contains(&LogSourceTag::LINUX_SYSLOG));
        let cont = p.parse_line("#0 {main}").expect("event");
        assert_eq!(cont.hostname.as_deref(), Some("web01"));
        assert!(cont.tags.contains(&LogSourceTag::LINUX_SYSLOG));
    }

    #[test]
    fn php2shell_fixture_parses_every_line() {
        let lines = fixture("test_files/php2shell/php-error.log");
        assert_eq!(lines.len(), 228);
        let mut p = PhpErrorParser::new(ctx("test_files/php2shell/php-error.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 228);
        assert!(
            events
                .iter()
                .all(|e| e.tz_explicit && !e.timestamp_inferred)
        );
        assert!(events.iter().all(|e| e.field_str("zone") == Some("UTC")));
        assert!(
            events
                .iter()
                .all(|e| e.tags == vec![LogSourceTag::PHP_ERROR_LOG])
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.field_str("php_type") == Some("Fatal error"))
                .count(),
            106
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.field_str("php_type") == Some("Warning"))
                .count(),
            122
        );
        assert!(events.iter().all(|e| e.field_str("file") == Some("Unknown")
            || e.field_str("file") == Some("Command line code")));
        assert_eq!(rfc(&events[0]), "2026-10-24T15:35:33+00:00");
        assert_eq!(rfc(&events[227]), "2026-10-24T18:57:31+00:00");
        assert!(
            events.windows(2).all(|w| w[0].timestamp <= w[1].timestamp),
            "fixture is time sorted"
        );
    }

    #[test]
    fn php2shell_fpm_fixture_parses_every_line() {
        let lines = fixture("test_files/php2shell-fpm/php-error.log");
        assert_eq!(lines.len(), 13);
        let mut p = PhpErrorParser::new(ctx("test_files/php2shell-fpm/php-error.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 13);
        let inferred: Vec<&str> = events
            .iter()
            .filter(|e| e.timestamp_inferred)
            .map(|e| e.raw.as_str())
            .collect();
        assert_eq!(
            inferred,
            vec![
                "Stack trace:",
                "#0 {main}",
                "  thrown in /var/www/html/x.php on line 3"
            ]
        );
        assert_eq!(rfc(&events[0]), "2026-10-26T11:00:59+01:00");
        assert_eq!(rfc(&events[6]), "2026-10-26T11:06:00+01:00");
        assert_eq!(events[6].field("php_type"), Some(&FieldValue::Null));
        assert_eq!(
            rfc(&events[7]),
            "2026-10-26T11:07:00+09:00",
            "no zone -> ctx.tz"
        );
        assert!(!events[7].tz_explicit);
        assert_eq!(rfc(&events[8]), "2026-10-26T11:08:00+09:00");
        assert!(events[8].tz_explicit);
        assert_eq!(
            rfc(&events[11]),
            "2026-10-26T11:08:00+09:00",
            "thrown in borrows"
        );
        assert_eq!(events[3].field_str("php_type"), Some("Warning"));
        assert!(
            events[3]
                .field_str("message")
                .is_some_and(|m| m.starts_with("POST Content-Length of 33128677 bytes"))
        );
        assert_eq!(events[12].field_str("file"), Some("Command line code"));
        assert!(!p.zone_warned);
    }

    // ----- PhpFpmParser ------------------------------------------------------------------

    #[test]
    fn fpm_notice_without_pool() {
        let mut p = PhpFpmParser::new(ctx("php8.3-fpm.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:00:00] NOTICE: fpm is running, pid 1")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00+09:00");
        assert!(!ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "php/fpm");
        assert_eq!(ev.tags, vec![LogSourceTag::PHP_FPM]);
        assert_eq!(keys(&ev), vec!["level", "pool", "child_pid", "message"]);
        assert_eq!(ev.field_str("level"), Some("NOTICE"));
        assert_eq!(ev.field("pool"), Some(&FieldValue::Null));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("message"), Some("fpm is running, pid 1"));
    }

    #[test]
    fn fpm_fraction_is_optional() {
        let mut p = PhpFpmParser::new(ctx("php8.3-fpm.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:00:00.123] NOTICE: fpm is running, pid 1")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00.123+09:00");
        let ev = p
            .parse_line("[26-Oct-2026 11:00:00.123456] DEBUG: pid 1, fpm_event_loop(), line 419: event module is epoll")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:00:00.123456+09:00");
        assert_eq!(ev.field_str("level"), Some("DEBUG"));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("pid 1, fpm_event_loop(), line 419: event module is epoll")
        );
    }

    #[test]
    fn fpm_pool_child_and_shell_stderr() {
        let mut p = PhpFpmParser::new(ctx("php8.3-fpm.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:01:00] WARNING: [pool www] child 2010 said into stderr: \"sh: 1: wget: not found\"")
            .expect("event");
        assert_eq!(ev.field_str("level"), Some("WARNING"));
        assert_eq!(ev.field_str("pool"), Some("www"));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Int(2010)));
        assert_eq!(
            ev.field_str("message"),
            Some("child 2010 said into stderr: \"sh: 1: wget: not found\"")
        );
        assert_eq!(
            ev.tags,
            vec![LogSourceTag::PHP_FPM],
            "shell output is not a PHP message"
        );
        let ev = p
            .parse_line("[26-Oct-2026 11:01:01] WARNING: [pool www] child 2010 exited on signal 11 (SIGSEGV - core dumped) after 120.512345 seconds from start")
            .expect("event");
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Int(2010)));
        assert!(
            ev.field_str("message")
                .is_some_and(|m| m.starts_with("child 2010 exited on signal 11 (SIGSEGV"))
        );
        let ev = p
            .parse_line("[26-Oct-2026 11:01:01] NOTICE: [pool www] child 2011 started")
            .expect("event");
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Int(2011)));
        assert_eq!(ev.field_str("message"), Some("child 2011 started"));
        let ev = p
            .parse_line("[26-Oct-2026 11:00:59] WARNING: [pool www] seems busy (you may need to increase pm.start_servers, or pm.min/max_spare_servers), spawning 8 children, there are 0 idle, and 5 total children")
            .expect("event");
        assert_eq!(ev.field_str("pool"), Some("www"));
        assert_eq!(
            ev.field("child_pid"),
            Some(&FieldValue::Null),
            "'children' is not 'child N'"
        );
        let ev = p
            .parse_line("[26-Oct-2026 11:01:02] ALERT: [pool www] user has not been defined")
            .expect("event");
        assert_eq!(ev.field_str("level"), Some("ALERT"));
        assert_eq!(ev.field_str("message"), Some("user has not been defined"));
    }

    #[test]
    fn fpm_stderr_php_warning_gets_the_php_tag() {
        let mut p = PhpFpmParser::new(ctx("php8.3-fpm.log"));
        let ev = p
            .parse_line("[26-Oct-2026 11:05:00] WARNING: [pool www] child 2012 said into stderr: \"PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0\"")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:05:00+09:00");
        assert_eq!(
            ev.tags,
            vec![LogSourceTag::PHP_FPM, LogSourceTag::PHP_ERROR_LOG]
        );
        assert_eq!(ev.primary_logsource, "php/fpm");
        assert_eq!(ev.field_str("pool"), Some("www"));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Int(2012)));
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(
            ev.field_str("php_message"),
            Some(
                "PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0"
            )
        );
        assert_eq!(ev.field_str("file"), Some("Unknown"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(0)));
        assert!(
            ev.field_str("message")
                .is_some_and(|m| m.starts_with("child 2012 said into stderr: \"PHP Warning:"))
        );
    }

    #[test]
    fn fpm_continuations_and_blank_lines() {
        let mut p = PhpFpmParser::new(ctx("php8.3-fpm.log"));
        assert!(p.parse_line("").is_none());
        let ev = p.parse_line("no header").expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.tags, vec![LogSourceTag::PHP_FPM]);
        let first = p
            .parse_line("[26-Oct-2026 11:00:00] NOTICE: ready to handle connections")
            .expect("event");
        let ev = p
            .parse_line("second line of a multi-line stderr")
            .expect("event");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(
            ev.field_str("message"),
            Some("second line of a multi-line stderr")
        );
        // an impossible child pid does not panic
        let ev = p
            .parse_line(
                "[26-Oct-2026 11:00:00] NOTICE: [pool www] child 99999999999999999999 started",
            )
            .expect("event");
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Null));
    }

    #[test]
    fn php_error_log_lines_inside_the_fpm_log_keep_their_own_timestamp() {
        crate::errorlog::set_quiet(true);
        let mut p = PhpFpmParser::new(ctx("php8.3-fpm.log"));
        let fpm = p
            .parse_line("[26-Oct-2026 11:00:00] NOTICE: ready to handle connections")
            .expect("event");
        // php-fpm and PHP sharing one error_log: not an fpm entry, but the line has its own date
        let ev = p
            .parse_line("[26-Oct-2026 11:07:00] PHP Warning:  foo in /x.php on line 3")
            .expect("event");
        assert_eq!(
            rfc(&ev),
            "2026-10-26T11:07:00+09:00",
            "ctx.tz, not borrowed"
        );
        assert!(!ev.timestamp_inferred);
        assert!(!ev.tz_explicit);
        assert_ne!(ev.timestamp, fpm.timestamp);
        assert_eq!(ev.primary_logsource, "php/fpm");
        assert_eq!(
            ev.tags,
            vec![LogSourceTag::PHP_FPM, LogSourceTag::PHP_ERROR_LOG]
        );
        assert_eq!(
            keys(&ev),
            vec![
                "level",
                "pool",
                "child_pid",
                "message",
                "zone",
                "php_type",
                "php_message",
                "file",
                "line"
            ]
        );
        assert_eq!(ev.field("level"), Some(&FieldValue::Null));
        assert_eq!(ev.field("pool"), Some(&FieldValue::Null));
        assert_eq!(ev.field("child_pid"), Some(&FieldValue::Null));
        assert_eq!(
            ev.field_str("message"),
            Some("PHP Warning:  foo in /x.php on line 3")
        );
        assert_eq!(ev.field("zone"), Some(&FieldValue::Null));
        assert_eq!(ev.field_str("php_type"), Some("Warning"));
        assert_eq!(ev.field_str("php_message"), Some("foo in /x.php on line 3"));
        assert_eq!(ev.field_str("file"), Some("/x.php"));
        assert_eq!(ev.field("line"), Some(&FieldValue::Int(3)));
        // a following continuation borrows the PHP line's timestamp, not the fpm entry's
        let cont = p.parse_line("Stack trace:").expect("event");
        assert_eq!(cont.timestamp, ev.timestamp);
        assert!(cont.timestamp_inferred);
        // zone tokens behave as in the PHP error log parser
        let ev = p
            .parse_line("[26-Oct-2026 11:08:00 UTC] PHP Notice:  bar")
            .expect("event");
        assert_eq!(rfc(&ev), "2026-10-26T11:08:00+00:00");
        assert!(ev.tz_explicit);
        assert_eq!(ev.field_str("zone"), Some("UTC"));
        assert!(!p.zone_warned);
        let ev = p
            .parse_line("[26-Oct-2026 11:09:00 JST] PHP Notice:  baz")
            .expect("event");
        assert_eq!(
            rfc(&ev),
            "2026-10-26T11:09:00+09:00",
            "unknown token -> ctx.tz"
        );
        assert!(!ev.tz_explicit);
        assert_eq!(ev.field_str("zone"), Some("JST"));
        assert!(p.zone_warned);
        // a user error_log() line: no PHP fields, no PHP tag
        let ev = p
            .parse_line(
                "[26-Oct-2026 11:10:00] WordPress database error Table 'wp.wp_options' doesn't exist",
            )
            .expect("event");
        assert_eq!(ev.tags, vec![LogSourceTag::PHP_FPM]);
        assert_eq!(ev.field("php_type"), None);
        assert_eq!(
            ev.field_str("message"),
            Some("WordPress database error Table 'wp.wp_options' doesn't exist")
        );
        assert_eq!(
            keys(&ev),
            vec!["level", "pool", "child_pid", "message", "zone"]
        );
        // an impossible date keeps the fields and borrows the previous timestamp
        let ev = p
            .parse_line("[32-Oct-2026 11:11:00] PHP Notice:  bad day")
            .expect("event");
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.field_str("php_type"), Some("Notice"));
    }

    #[test]
    fn fpm_fixture_parses_every_line() {
        let lines = fixture("test_files/php2shell-fpm/php8.3-fpm.log");
        assert_eq!(lines.len(), 8);
        let mut p = PhpFpmParser::new(ctx("test_files/php2shell-fpm/php8.3-fpm.log"));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| p.parse_line(l)).collect();
        assert_eq!(events.len(), 8);
        assert!(
            events
                .iter()
                .all(|e| !e.timestamp_inferred && !e.tz_explicit)
        );
        assert!(events.iter().all(|e| e.tags[0] == LogSourceTag::PHP_FPM));
        assert_eq!(
            events
                .iter()
                .filter(|e| e.tags.contains(&LogSourceTag::PHP_ERROR_LOG))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.field_str("pool") == Some("www"))
                .count(),
            6
        );
        assert_eq!(rfc(&events[0]), "2026-10-26T11:00:00+09:00");
        assert_eq!(events[4].field("child_pid"), Some(&FieldValue::Int(2010)));
        assert_eq!(events[7].field("child_pid"), Some(&FieldValue::Int(2012)));
    }

    #[test]
    fn quoted_php_text_counts_only_after_the_known_wrappers() {
        // An attacker-controlled request path or header quoting PHP text is not a PHP message.
        assert!(detect_php_message(
            "AH00126: Invalid URI in request GET /'PHP Fatal error:  Allowed memory size of 1 bytes exhausted in Unknown on line 0 HTTP/1.1"
        )
        .is_none());
        assert!(detect_php_message(
            "client sent invalid header line: \"X-A: \"PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters\""
        )
        .is_none());
        for wrapped in [
            "AH01071: Got error 'PHP Fatal error:  x in Unknown on line 0'",
            "child 2 said into stderr: \"PHP Warning:  y in /a.php on line 3\"",
            "FastCGI sent in stderr: \"PHP Notice:  z in /b.php on line 4\" while reading",
        ] {
            assert!(detect_php_message(wrapped).is_some(), "{wrapped}");
        }
    }

    #[test]
    fn location_is_found_before_joined_messages_and_wrappers() {
        assert_eq!(
            split_location(r"Undefined variable $a in /var/www/a.php on line 3\n"),
            (Some("/var/www/a.php".to_string()), Some(3))
        );
        assert_eq!(
            split_location("a in /x.php on line 1;"),
            (Some("/x.php".to_string()), Some(1))
        );
        assert_eq!(
            split_location("x in Unknown on line 0'"),
            (Some("Unknown".to_string()), Some(0))
        );
    }
}
