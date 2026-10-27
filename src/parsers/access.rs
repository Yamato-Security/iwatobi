//! Web server access logs: text (common / combined / Apache `vhost_combined` / nginx `combined`,
//! tolerant of trailing extra fields) and JSON lines (Apache/nginx JSON `LogFormat`s, the
//! honeypot `web.jsonl`).
//!
//! Fields follow the Sigma `webserver` taxonomy; see design §4.2, §4.3 and amendments A2, A9 and
//! A10. Every access event carries the complete taxonomy key set, with `Null` for whatever the
//! line did not have: sigma-rust treats a *missing* field as "no match", so `cs-referer: null`
//! (how SigmaHQ's reGeorg rule tests for an absent Referer) only works when the key is present.
//! `sc-status` and `sc-bytes` are always `Int` (or `Null`), never strings, so `sc-status|gte: 400`
//! compares numbers.

use super::timestamp::{self, Resolution, TzAssumption};
use super::{LineParser, ParseContext, continuation_event};
use crate::errorlog::log_warn;
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
use regex::Regex;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use std::borrow::Cow;
use std::fmt;
use std::sync::LazyLock;

/// Common / combined / vhost_combined / nginx combined entry (design §4.2). Quoted fields accept
/// backslash-escaped characters; anything after the user agent is `extra`.
static ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(?:(?P<vhost>[^\s"]+?:\d+) )?(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-)(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?(?P<extra>.*)$"#,
    )
    .expect("access log entry regex is valid")
});

/// The first taxonomy keys of an access log event (shown first in `Details`), in order.
const DETAILS_KEYS: [&str; 7] = [
    "c-ip",
    "cs-method",
    "cs-uri-query",
    "sc-status",
    "sc-bytes",
    "cs-referer",
    "cs-user-agent",
];

/// The taxonomy keys that follow them, in order.
const EXTRA_KEYS: [&str; 6] = [
    "cs-uri-stem",
    "cs-uri",
    "cs-version",
    "cs-username",
    "cs-host",
    "c-useragent",
];

// JSON key aliases (design §4.3): case-insensitive, first alias with a value wins. The taxonomy
// name itself is accepted first so that a log that already follows the Sigma taxonomy maps 1:1.
const C_IP_ALIASES: &[&str] = &[
    "c-ip",
    "remote_addr",
    "remote_ip",
    "client_ip",
    "clientip",
    "client",
    "peerIp",
    "peer_ip",
    "src_ip",
    "srcip",
    "ip",
];
const METHOD_ALIASES: &[&str] = &[
    "cs-method",
    "method",
    "request_method",
    "http_method",
    "verb",
];
const TARGET_ALIASES: &[&str] = &[
    "cs-uri",
    "uri",
    "request_uri",
    "url",
    "path",
    "request_path",
];
/// A separate query-string key, appended to the target when the target carries no `?`.
const QUERY_ALIASES: &[&str] = &[
    "args",
    "query",
    "query_string",
    "querystring",
    "request_query",
];
const VERSION_ALIASES: &[&str] = &[
    "cs-version",
    "proto",
    "protocol",
    "server_protocol",
    "http_version",
    "version",
];
const STATUS_ALIASES: &[&str] = &[
    "sc-status",
    "status",
    "status_code",
    "response_code",
    "sc_status",
];
const BYTES_ALIASES: &[&str] = &[
    "sc-bytes",
    "bytes",
    "bytes_sent",
    "body_bytes_sent",
    "respBytes",
    "resp_bytes",
    "response_bytes",
    "size",
];
const REFERER_ALIASES: &[&str] = &[
    "cs-referer",
    "referer",
    "referrer",
    "http_referer",
    "http_referrer",
];
const UA_ALIASES: &[&str] = &[
    "cs-user-agent",
    "c-useragent",
    "user_agent",
    "useragent",
    "http_user_agent",
    "ua",
    "agent",
];
const HOST_ALIASES: &[&str] = &["cs-host", "host", "vhost", "server_name", "http_host"];
const USERNAME_ALIASES: &[&str] = &[
    "cs-username",
    "user",
    "remote_user",
    "username",
    "auth_user",
];
/// Timestamp keys, tried in this order (design §4.3 / amendment A7).
pub(super) const TIME_KEYS: &[&str] = &[
    "ts",
    "time",
    "timestamp",
    "@timestamp",
    "time_local",
    "time_iso8601",
    "datetime",
    "date",
    "msec",
    "time_msec",
    "timestamp_ms",
];

/// Whether `line` is a common/combined access log entry.
pub fn matches_entry(line: &str) -> bool {
    ENTRY_RE.is_match(line)
}

/// Whether `line` is a JSON object that looks like an access record: it has a method-ish AND a
/// status-ish key, or a `request` key (design §4.3).
pub fn matches_json_entry(line: &str) -> bool {
    let Some(object) = parse_json_object(line) else {
        return false;
    };
    let mut fields = Vec::with_capacity(object.len());
    flatten(&object, "", &mut fields);
    let has = |aliases: &[&str]| !matches!(lookup(&fields, aliases), Looked::Missing);
    (has(METHOD_ALIASES) && has(STATUS_ALIASES)) || has(&["request"])
}

/// Tags every event of an access log carries besides `WEBSERVER` (amendment A9).
pub(super) fn product_tags(product: Option<&str>) -> Vec<LogSourceTag> {
    match product {
        Some("apache") => vec![LogSourceTag::APACHE_WEBSERVER, LogSourceTag::APACHE_ACCESS],
        Some("nginx") => vec![LogSourceTag::NGINX_WEBSERVER, LogSourceTag::NGINX_ACCESS],
        _ => Vec::new(),
    }
}

/// Whether `key` is a name the taxonomy mapping or the timestamp reads (an alias, `request`, a
/// time key).
fn is_mapped_key(key: &str) -> bool {
    [
        C_IP_ALIASES,
        METHOD_ALIASES,
        TARGET_ALIASES,
        QUERY_ALIASES,
        VERSION_ALIASES,
        STATUS_ALIASES,
        BYTES_ALIASES,
        REFERER_ALIASES,
        UA_ALIASES,
        HOST_ALIASES,
        USERNAME_ALIASES,
        TIME_KEYS,
        &["request"],
    ]
    .iter()
    .any(|aliases| aliases.iter().any(|a| a.eq_ignore_ascii_case(key)))
}

/// Whether `key` is one of the 13 taxonomy keys this module owns.
fn is_taxonomy_key(key: &str) -> bool {
    DETAILS_KEYS
        .iter()
        .chain(EXTRA_KEYS.iter())
        .any(|k| k.eq_ignore_ascii_case(key))
}

// ------------------------------------------------------------------------------------------------
// Request line (amendment A10)
// ------------------------------------------------------------------------------------------------

/// The parts of a CLF request line `METHOD TARGET VERSION`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RequestLine {
    pub(super) method: Option<String>,
    pub(super) target: Option<String>,
    pub(super) version: Option<String>,
}

/// Split a request line on spaces: the first token is the method if it is all uppercase
/// letters, the last token is the version if it looks like `HTTP/1.1`, and whatever remains,
/// rejoined with single spaces, is the target. `-` and an empty string give no parts at all.
pub(super) fn parse_request_line(req: &str) -> RequestLine {
    let mut tokens: Vec<&str> = req.split(' ').filter(|t| !t.is_empty()).collect();
    if tokens.is_empty() || (tokens.len() == 1 && tokens[0] == "-") {
        return RequestLine::default();
    }
    let mut parts = RequestLine::default();
    if tokens.first().is_some_and(|t| is_http_method(t)) {
        parts.method = Some(tokens.remove(0).to_string());
    }
    if tokens.last().is_some_and(|t| is_http_version(t)) {
        parts.version = tokens.pop().map(str::to_string);
    }
    if !tokens.is_empty() {
        parts.target = Some(tokens.join(" "));
    }
    parts
}

/// `^[A-Z]+$`
pub(super) fn is_http_method(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_uppercase())
}

/// `^HTTP/\d(\.\d)?$`
pub(super) fn is_http_version(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("HTTP/") else {
        return false;
    };
    match rest.as_bytes() {
        [major] => major.is_ascii_digit(),
        [major, b'.', minor] => major.is_ascii_digit() && minor.is_ascii_digit(),
        _ => false,
    }
}

/// The request target up to (not including) the first `?`.
fn uri_stem(target: &str) -> &str {
    target.split_once('?').map_or(target, |(stem, _)| stem)
}

/// Undo the escaping Apache and nginx apply inside quoted fields for the two characters that
/// would otherwise break the quoting: `\"` → `"` and `\\` → `\`. Other escapes (`\xHH`, `\n`)
/// are kept verbatim so that control characters never reach the output.
pub(super) fn unescape_quoted(s: &str) -> Cow<'_, str> {
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('"') => {
                    out.push('"');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                // nginx escapes `"` and `\` as `\x22` / `\x5C` (other `\xHH` stay as written).
                Some('x') | Some('X') => {
                    let mut look = chars.clone();
                    look.next();
                    let hex: String = look.by_ref().take(2).collect();
                    match hex.to_ascii_uppercase().as_str() {
                        "22" => {
                            out.push('"');
                            chars = look;
                        }
                        "5C" => {
                            out.push('\\');
                            chars = look;
                        }
                        _ => out.push('\\'),
                    }
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

// ------------------------------------------------------------------------------------------------
// Taxonomy fields (amendment A2)
// ------------------------------------------------------------------------------------------------

/// The Sigma `webserver` taxonomy values of one access event.
#[derive(Clone, Debug, PartialEq)]
struct Taxonomy {
    c_ip: FieldValue,
    cs_method: FieldValue,
    /// The full request target (`path?query`): `cs-uri` and `cs-uri-query`; `cs-uri-stem` is
    /// derived from it.
    target: FieldValue,
    cs_version: FieldValue,
    sc_status: FieldValue,
    sc_bytes: FieldValue,
    cs_referer: FieldValue,
    cs_user_agent: FieldValue,
    cs_host: FieldValue,
    cs_username: FieldValue,
}

impl Taxonomy {
    fn null() -> Self {
        Self {
            c_ip: FieldValue::Null,
            cs_method: FieldValue::Null,
            target: FieldValue::Null,
            cs_version: FieldValue::Null,
            sc_status: FieldValue::Null,
            sc_bytes: FieldValue::Null,
            cs_referer: FieldValue::Null,
            cs_user_agent: FieldValue::Null,
            cs_host: FieldValue::Null,
            cs_username: FieldValue::Null,
        }
    }

    /// Push the seven `Details` keys, close the details, then the six `Extra` taxonomy keys.
    fn push_into(self, ev: &mut ParsedEvent) {
        let stem = match &self.target {
            FieldValue::Str(t) => FieldValue::str_or_null(uri_stem(t)),
            _ => FieldValue::Null,
        };
        ev.push("c-ip", self.c_ip);
        ev.push("cs-method", self.cs_method);
        ev.push("cs-uri-query", self.target.clone());
        ev.push("sc-status", self.sc_status);
        ev.push("sc-bytes", self.sc_bytes);
        ev.push("cs-referer", self.cs_referer);
        ev.push("cs-user-agent", self.cs_user_agent.clone());
        ev.push("cs-uri-stem", stem);
        ev.push("cs-uri", self.target);
        ev.push("cs-version", self.cs_version);
        ev.push("cs-username", self.cs_username);
        ev.push("cs-host", self.cs_host);
        ev.push("c-useragent", self.cs_user_agent);
    }

    /// Taxonomy values from the flattened keys of a JSON record (design §4.3).
    fn from_json(fields: &[(String, FieldValue)]) -> Self {
        let mut t = Taxonomy::null();
        t.c_ip = coerce_str(lookup(fields, C_IP_ALIASES));
        t.cs_method = coerce_str(lookup(fields, METHOD_ALIASES));
        t.target = coerce_str(lookup(fields, TARGET_ALIASES));
        t.cs_version = coerce_str(lookup(fields, VERSION_ALIASES));
        // `request` holds a CLF request line: it fills whatever the dedicated keys did not.
        if let Looked::Value(FieldValue::Str(request)) = lookup(fields, &["request"]) {
            let parts = parse_request_line(request);
            if t.cs_method == FieldValue::Null {
                t.cs_method = parts.method.into();
            }
            if t.target == FieldValue::Null {
                t.target = parts.target.into();
            }
            if t.cs_version == FieldValue::Null {
                t.cs_version = parts.version.into();
            }
        }
        // nginx `$uri` + `$args`: rebuild the full target when the query string is separate.
        if let FieldValue::Str(target) = &t.target
            && !target.contains('?')
            && let FieldValue::Str(query) = coerce_str(lookup(fields, QUERY_ALIASES))
        {
            let query = query.strip_prefix('?').unwrap_or(&query);
            if !query.is_empty() {
                t.target = FieldValue::Str(format!("{target}?{query}"));
            }
        }
        t.sc_status = match lookup(fields, STATUS_ALIASES) {
            Looked::Value(v) => coerce_int(v),
            Looked::Empty(_) | Looked::Missing => FieldValue::Null,
        };
        t.sc_bytes = match lookup(fields, BYTES_ALIASES) {
            Looked::Value(v) => coerce_int(v),
            // the CLF dash (or an empty string) means "nothing sent"; JSON null says nothing
            Looked::Empty(FieldValue::Str(_)) => FieldValue::Int(0),
            Looked::Empty(_) | Looked::Missing => FieldValue::Null,
        };
        t.cs_referer = coerce_str(lookup(fields, REFERER_ALIASES));
        t.cs_user_agent = coerce_str(lookup(fields, UA_ALIASES));
        t.cs_host = coerce_str(lookup(fields, HOST_ALIASES));
        t.cs_username = coerce_str(lookup(fields, USERNAME_ALIASES));
        t
    }
}

/// `sc-bytes` of a text line: `-` means "nothing sent" (`Int(0)`), a number is itself, and
/// anything unparsable (an absurdly long digit run) is `Null`.
fn bytes_from_text(s: &str) -> FieldValue {
    if s.is_empty() || s == "-" {
        FieldValue::Int(0)
    } else {
        FieldValue::int_or_null(s)
    }
}

/// Result of an alias lookup in a JSON record.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Looked<'a> {
    /// A key with a usable value.
    Value(&'a FieldValue),
    /// Only keys whose value is `null`, `""` or `-` (the first such value).
    Empty(&'a FieldValue),
    /// No alias is present.
    Missing,
}

fn is_empty_value(v: &FieldValue) -> bool {
    match v {
        FieldValue::Null => true,
        FieldValue::Str(s) => s.is_empty() || s == "-",
        _ => false,
    }
}

/// Find the first alias (case-insensitive) with a value. Exact keys are tried for every alias
/// first; then the same names inside a nested `request` object (`request.method`, as Caddy and
/// some structured loggers write), so that a flattened `request.*` block still maps.
fn lookup<'a>(fields: &'a [(String, FieldValue)], aliases: &[&str]) -> Looked<'a> {
    let mut empty: Option<&'a FieldValue> = None;
    for nested in [false, true] {
        for alias in aliases {
            for (key, value) in fields {
                let hit = if nested {
                    key.strip_prefix("request.")
                        .or_else(|| key.strip_prefix("Request."))
                        .is_some_and(|rest| rest.eq_ignore_ascii_case(alias))
                } else {
                    key.eq_ignore_ascii_case(alias)
                };
                if !hit {
                    continue;
                }
                if is_empty_value(value) {
                    empty.get_or_insert(value);
                } else {
                    return Looked::Value(value);
                }
            }
        }
    }
    empty.map_or(Looked::Missing, Looked::Empty)
}

/// The exact (case-insensitive) key, if present.
pub(super) fn exact_field<'a>(
    fields: &'a [(String, FieldValue)],
    key: &str,
) -> Option<&'a FieldValue> {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

/// A string taxonomy value: `-`/empty/null → `Null`, numbers and booleans rendered as text.
fn coerce_str(looked: Looked<'_>) -> FieldValue {
    match looked {
        Looked::Value(FieldValue::Str(s)) => FieldValue::str_or_null(s),
        Looked::Value(FieldValue::Null) | Looked::Empty(_) | Looked::Missing => FieldValue::Null,
        Looked::Value(other) => FieldValue::Str(other.render()),
    }
}

/// An integer taxonomy value (`sc-status`, `sc-bytes`): numbers and numeric-looking strings
/// become `Int`, everything else `Null`. Never a string (amendment A2).
/// Numeric fields of the Sigma web server taxonomy (and process ids) besides `sc-status` and
/// `sc-bytes`, which the taxonomy mapping already types.
const NUMERIC_KEYS: &[&str] = &["s-port", "cs-bytes", "time-taken", "pid", "tid"];

fn coerce_int(v: &FieldValue) -> FieldValue {
    match v {
        FieldValue::Int(i) => FieldValue::Int(*i),
        FieldValue::Float(f) => integral(*f).map_or(FieldValue::Null, FieldValue::Int),
        FieldValue::Str(s) => {
            let t = s.trim();
            if let Ok(i) = t.parse::<i64>() {
                FieldValue::Int(i)
            } else if let Ok(f) = t.parse::<f64>() {
                integral(f).map_or(FieldValue::Null, FieldValue::Int)
            } else {
                FieldValue::Null
            }
        }
        FieldValue::Bool(_) | FieldValue::Null => FieldValue::Null,
    }
}

/// A float that is a whole number (and small enough to be exact) as an `i64`.
fn integral(f: f64) -> Option<i64> {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        Some(f as i64)
    } else {
        None
    }
}

// ------------------------------------------------------------------------------------------------
// Timestamps
// ------------------------------------------------------------------------------------------------

/// Parse any textual timestamp an access log may carry: CLF (`26/Oct/2026:17:39:01 +0900`),
/// RFC 3339 / ISO 8601 with a zone, epoch seconds/milliseconds/microseconds, and ISO without a
/// zone (resolved in the assumed zone). Returns the instant, whether the text carried its own
/// zone, and how a naive time was resolved.
pub(super) fn parse_time_text(
    s: &str,
    tz: &TzAssumption,
) -> Option<(DateTime<FixedOffset>, bool, Resolution)> {
    let t = s.trim();
    if t.is_empty() || t == "-" {
        return None;
    }
    if let Some(dt) = timestamp::parse_clf_time(t) {
        return Some((dt, true, Resolution::Exact));
    }
    if let Some(dt) = timestamp::parse_iso_with_zone(t) {
        return Some((dt, true, Resolution::Exact));
    }
    if looks_numeric(t)
        && let Ok(n) = t.parse::<f64>()
    {
        return timestamp::parse_epoch(n).map(|dt| (dt.fixed_offset(), true, Resolution::Exact));
    }
    let dashed = slashes_to_dashes(t);
    if let Some(naive) = timestamp::parse_iso_naive(&dashed) {
        let (dt, res) = timestamp::resolve_naive(naive, tz);
        return Some((dt, false, res));
    }
    // `2026-10-26 12:20:00 +0900`: a zone after a space
    if let Some((head, zone)) = t.rsplit_once(' ')
        && let Some(offset) = timestamp::parse_fixed_offset(zone)
        && let Some(naive) = timestamp::parse_iso_naive(&slashes_to_dashes(head))
    {
        return offset
            .from_local_datetime(&naive)
            .single()
            .map(|dt| (dt, true, Resolution::Exact));
    }
    None
}

/// Digits with at most one `.`: an epoch value written as a string.
fn looks_numeric(t: &str) -> bool {
    t.starts_with(|c: char| c.is_ascii_digit())
        && t.chars().all(|c| c.is_ascii_digit() || c == '.')
        && t.matches('.').count() <= 1
}

/// `2026/10/26 12:20:00` → `2026-10-26 12:20:00` (only the date separators).
fn slashes_to_dashes(t: &str) -> Cow<'_, str> {
    let b = t.as_bytes();
    if b.len() >= 10
        && b[4] == b'/'
        && b[7] == b'/'
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        let mut out = t.to_string();
        out.replace_range(4..5, "-");
        out.replace_range(7..8, "-");
        Cow::Owned(out)
    } else {
        Cow::Borrowed(t)
    }
}

/// A `date` key (`2026-10-26`, `2026/10/26`) combined with the `time` key when there is one,
/// otherwise midnight.
fn combine_date_time(
    date: &str,
    fields: &[(String, FieldValue)],
    tz: &TzAssumption,
) -> Option<(DateTime<FixedOffset>, bool, Resolution)> {
    let dashed = slashes_to_dashes(date.trim());
    let day = NaiveDate::parse_from_str(&dashed, "%Y-%m-%d").ok()?;
    let time = exact_field(fields, "time")
        .and_then(FieldValue::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "-");
    match time {
        Some(time) => parse_time_text(&format!("{} {time}", day.format("%Y-%m-%d")), tz),
        None => {
            let naive = day.and_hms_opt(0, 0, 0)?;
            let (dt, res) = timestamp::resolve_naive(naive, tz);
            Some((dt, false, res))
        }
    }
}

/// Record (once per file) that a zone-less timestamp was ambiguous or fell in a DST gap.
pub(super) fn warn_resolution(ctx: &ParseContext, warned: &mut bool, res: Resolution) {
    if *warned {
        return;
    }
    let what = match res {
        Resolution::Exact => return,
        Resolution::Ambiguous => "is ambiguous (clocks went back); the earliest instant was used",
        Resolution::Gap => "falls in a DST gap (clocks went forward); it was moved one hour later",
    };
    *warned = true;
    log_warn(&format!(
        "{}: a timestamp without a zone {what} in timezone {}",
        ctx.display_name, ctx.tz
    ));
}

// ------------------------------------------------------------------------------------------------
// Text access log
// ------------------------------------------------------------------------------------------------

pub struct AccessLogParser {
    ctx: ParseContext,
    tags: Vec<LogSourceTag>,
    last_ts: Option<DateTime<FixedOffset>>,
    warned_resolution: bool,
}

impl AccessLogParser {
    pub fn new(ctx: ParseContext) -> Self {
        let tags = product_tags(ctx.hints.product);
        Self {
            ctx,
            tags,
            last_ts: None,
            warned_resolution: false,
        }
    }

    fn continuation(&self, line: &str) -> ParsedEvent {
        let mut ev = continuation_event(line, &LogSourceTag::WEBSERVER, &self.tags, self.last_ts);
        self.ctx.finish(&mut ev);
        ev
    }
}

impl LineParser for AccessLogParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let Some(caps) = ENTRY_RE.captures(line) else {
            return Some(self.continuation(line));
        };
        let group = |name: &str| caps.name(name).map_or("", |m| m.as_str());

        let mut ev = ParsedEvent::new(line, &LogSourceTag::WEBSERVER);
        ev.add_tags(&self.tags);
        match parse_time_text(group("time"), &self.ctx.tz) {
            Some((dt, explicit, res)) => {
                warn_resolution(&self.ctx, &mut self.warned_resolution, res);
                ev.timestamp = Some(dt);
                ev.tz_explicit = explicit;
                self.last_ts = Some(dt);
            }
            None => {
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }

        let request = unescape_quoted(group("req"));
        let parts = parse_request_line(&request);
        let quoted = |name: &str| {
            caps.name(name).map_or(FieldValue::Null, |m| {
                FieldValue::str_or_null(&unescape_quoted(m.as_str()))
            })
        };
        Taxonomy {
            c_ip: FieldValue::str_or_null(group("ip")),
            cs_method: parts.method.into(),
            target: parts.target.into(),
            cs_version: parts.version.into(),
            sc_status: FieldValue::int_or_null(group("status")),
            sc_bytes: bytes_from_text(group("bytes")),
            cs_referer: quoted("ref"),
            cs_user_agent: quoted("ua"),
            cs_host: caps
                .name("vhost")
                .map_or(FieldValue::Null, |m| FieldValue::str_or_null(m.as_str())),
            cs_username: FieldValue::str_or_null(group("user")),
        }
        .push_into(&mut ev);
        let ident = group("ident");
        if !ident.is_empty() && ident != "-" {
            ev.push("ident", ident);
        }
        let extra = group("extra").trim();
        if !extra.is_empty() {
            ev.push("extra", extra);
        }
        self.ctx.finish(&mut ev);
        Some(ev)
    }
}

// ------------------------------------------------------------------------------------------------
// JSON access log
// ------------------------------------------------------------------------------------------------

/// A JSON value that keeps object keys in document order (serde_json's `Map` sorts them, and
/// the `Extra` column should read like the log line does).
#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;

        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Json;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Json, E> {
                Ok(Json::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Json, E> {
                Ok(Json::Int(v))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Json, E> {
                Ok(Json::UInt(v))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Json, E> {
                Ok(Json::Float(v))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Json, E> {
                Ok(Json::Str(v.to_string()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Json, E> {
                Ok(Json::Str(v))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }

            fn visit_none<E: de::Error>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }

            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Json, D::Error> {
                Json::deserialize(d)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<Json>()? {
                    out.push(v);
                }
                Ok(Json::Array(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
                let mut out: Vec<(String, Json)> = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, Json>()? {
                    // a repeated key keeps its first position but takes the last value, which is
                    // what serde_json's map does too
                    if let Some(slot) = out.iter_mut().find(|(key, _)| *key == k) {
                        slot.1 = v;
                    } else {
                        out.push((k, v));
                    }
                }
                Ok(Json::Object(out))
            }
        }

        deserializer.deserialize_any(JsonVisitor)
    }
}

impl Json {
    /// serde_json representation (for rendering arrays as text).
    fn to_value(&self) -> serde_json::Value {
        match self {
            Json::Null => serde_json::Value::Null,
            Json::Bool(b) => serde_json::Value::Bool(*b),
            Json::Int(i) => serde_json::Value::from(*i),
            Json::UInt(u) => serde_json::Value::from(*u),
            Json::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Json::Str(s) => serde_json::Value::String(s.clone()),
            Json::Array(a) => serde_json::Value::Array(a.iter().map(Json::to_value).collect()),
            Json::Object(o) => serde_json::Value::Object(
                o.iter().map(|(k, v)| (k.clone(), v.to_value())).collect(),
            ),
        }
    }
}

/// `line` as a JSON object, in document key order.
fn parse_json_object(line: &str) -> Option<Vec<(String, Json)>> {
    let t = line.trim();
    if !(t.starts_with('{') && t.ends_with('}')) {
        return None;
    }
    match serde_json::from_str::<Json>(t) {
        Ok(Json::Object(o)) => Some(o),
        _ => None,
    }
}

/// Flatten an object into `(key, value)` pairs: nested objects join their keys with `.`, arrays
/// are kept as their JSON text, numbers become `Int` when they are whole numbers and `Float`
/// otherwise, `null` becomes `Null`.
fn flatten(object: &[(String, Json)], prefix: &str, out: &mut Vec<(String, FieldValue)>) {
    for (k, v) in object {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            Json::Object(inner) if !inner.is_empty() => flatten(inner, &key, out),
            Json::Object(_) => out.push((key, FieldValue::Null)),
            Json::Array(_) => out.push((key, FieldValue::Str(v.to_value().to_string()))),
            Json::Null => out.push((key, FieldValue::Null)),
            Json::Bool(b) => out.push((key, FieldValue::Bool(*b))),
            Json::Int(i) => out.push((key, FieldValue::Int(*i))),
            Json::UInt(u) => out.push((
                key,
                i64::try_from(*u).map_or(FieldValue::Float(*u as f64), FieldValue::Int),
            )),
            // A float stays a float even when it is whole (`2.000`): one field must not change
            // type with its value, because sigma-rust never compares Int with Float. The
            // taxonomy keys get their own Int coercion (A2).
            Json::Float(f) => out.push((key, FieldValue::Float(*f))),
            Json::Str(s) => out.push((key, FieldValue::Str(s.clone()))),
        }
    }
}

/// Turns the named fields of one access record (a JSON line, or the captures of a custom or
/// detected text layout) into a `webserver` event: the taxonomy keys mapped through the alias
/// tables, then every other field under its own name.
pub(super) struct RecordBuilder {
    ctx: ParseContext,
    tags: Vec<LogSourceTag>,
    last_ts: Option<DateTime<FixedOffset>>,
    warned_resolution: bool,
    /// A chrono `strftime` format for the time field (custom formats); otherwise any timestamp
    /// shape [`parse_time_text`] knows is accepted.
    time_format: Option<String>,
    /// A text layout (custom format or detected layout): its column names come from the layout,
    /// not the log, so the columns already mapped to the taxonomy and the time are not repeated,
    /// and `-` (or nothing), how such logs write an absent value, becomes `Null`.
    text_layout: bool,
}

impl RecordBuilder {
    pub(super) fn new(
        ctx: ParseContext,
        tags: Vec<LogSourceTag>,
        time_format: Option<String>,
        text_layout: bool,
    ) -> Self {
        Self {
            ctx,
            tags,
            last_ts: None,
            warned_resolution: false,
            time_format,
            text_layout,
        }
    }

    pub(super) fn continuation(&self, line: &str) -> ParsedEvent {
        let mut ev = continuation_event(line, &LogSourceTag::WEBSERVER, &self.tags, self.last_ts);
        self.ctx.finish(&mut ev);
        ev
    }

    /// The record's timestamp from the first `TIME_KEYS` entry that parses, and whether it
    /// carried its own zone.
    fn timestamp(
        &mut self,
        fields: &[(String, FieldValue)],
    ) -> Option<(DateTime<FixedOffset>, bool)> {
        let parsed = record_timestamp(fields, &self.ctx.tz, self.time_format.as_deref());
        let (dt, explicit, res) = parsed?;
        warn_resolution(&self.ctx, &mut self.warned_resolution, res);
        Some((dt, explicit))
    }

    pub(super) fn event(&mut self, line: &str, fields: Vec<(String, FieldValue)>) -> ParsedEvent {
        let mut ev = ParsedEvent::new(line, &LogSourceTag::WEBSERVER);
        ev.add_tags(&self.tags);
        match self.timestamp(&fields) {
            Some((dt, explicit)) => {
                ev.timestamp = Some(dt);
                ev.tz_explicit = explicit;
                self.last_ts = Some(dt);
            }
            None => {
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }
        Taxonomy::from_json(&fields).push_into(&mut ev);
        for (key, value) in fields {
            // The taxonomy owns these names; a record that already uses them was mapped above.
            if !is_taxonomy_key(&key) && !(self.text_layout && is_mapped_key(&key)) {
                // The other numeric taxonomy fields of A2 are numbers even when the log format
                // quotes them (nginx `escape=json`), so `s-port: 443` matches.
                let value = match &value {
                    FieldValue::Str(s) if NUMERIC_KEYS.contains(&key.as_str()) => s
                        .trim()
                        .parse::<i64>()
                        .map_or(value.clone(), FieldValue::Int),
                    FieldValue::Str(s) if self.text_layout && (s.is_empty() || s == "-") => {
                        FieldValue::Null
                    }
                    _ => value,
                };
                ev.push(&key, value);
            }
        }
        self.ctx.finish(&mut ev);
        ev
    }
}

/// The timestamp of a record of named fields: the first `TIME_KEYS` entry that parses (with
/// `time_format` when one is given), the instant, whether it carried its own zone, and how a
/// naive time was resolved.
pub(super) fn record_timestamp(
    fields: &[(String, FieldValue)],
    tz: &TzAssumption,
    time_format: Option<&str>,
) -> Option<(DateTime<FixedOffset>, bool, Resolution)> {
    for key in TIME_KEYS {
        let Some(value) = exact_field(fields, key) else {
            continue;
        };
        let parsed = match value {
            FieldValue::Int(i) => timestamp::parse_epoch(*i as f64)
                .map(|dt| (dt.fixed_offset(), true, Resolution::Exact)),
            FieldValue::Float(f) => {
                timestamp::parse_epoch(*f).map(|dt| (dt.fixed_offset(), true, Resolution::Exact))
            }
            FieldValue::Str(s) => match time_format {
                Some(format) => parse_time_with_format(s, format, tz),
                None => parse_time_text(s, tz).or_else(|| {
                    if key.eq_ignore_ascii_case("date") {
                        combine_date_time(s, fields, tz)
                    } else {
                        None
                    }
                }),
            },
            FieldValue::Bool(_) | FieldValue::Null => None,
        };
        if parsed.is_some() {
            return parsed;
        }
    }
    None
}

/// Parse `s` with a chrono `strftime` format: with a zone (`%z`, `%:z`) the time is exact,
/// without one it is resolved in the assumed zone, and a date-only format means midnight.
pub(super) fn parse_time_with_format(
    s: &str,
    format: &str,
    tz: &TzAssumption,
) -> Option<(DateTime<FixedOffset>, bool, Resolution)> {
    let t = s.trim();
    if let Ok(dt) = DateTime::parse_from_str(t, format) {
        return Some((dt, true, Resolution::Exact));
    }
    let naive = chrono::NaiveDateTime::parse_from_str(t, format)
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(t, format)
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
        })?;
    let (dt, res) = timestamp::resolve_naive(naive, tz);
    Some((dt, false, res))
}

pub struct AccessJsonParser {
    builder: RecordBuilder,
}

impl AccessJsonParser {
    pub fn new(ctx: ParseContext) -> Self {
        let tags = product_tags(ctx.hints.product);
        Self {
            builder: RecordBuilder::new(ctx, tags, None, false),
        }
    }
}

impl LineParser for AccessJsonParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let Some(object) = parse_json_object(line) else {
            return Some(self.builder.continuation(line));
        };
        let mut fields = Vec::with_capacity(object.len() + 8);
        flatten(&object, "", &mut fields);
        Some(self.builder.event(line, fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logsource::LogSourceSpec;
    use std::path::Path;

    const APACHE_LOG: &str = "/var/log/apache2/access.log";
    const NGINX_JSON: &str = "/var/log/nginx/access.json";
    const APACHE_FIXTURE: &str = "test_files/web/apache2/access.log";
    const NGINX_FIXTURE: &str = "test_files/web/nginx/access.json";
    const HONEYPOT_JSON: &str = "test_files/php2shell/apache2/access.jsonl";
    const HONEYPOT_LOG: &str = "test_files/php2shell/apache2/access.log";
    const POC_QUERY: &str = "/?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v";

    fn jst() -> TzAssumption {
        TzAssumption::Fixed(FixedOffset::east_opt(9 * 3600).expect("valid offset"))
    }

    fn ctx(path: &str) -> ParseContext {
        ParseContext::new(Path::new(path), jst())
    }

    fn parse_text(line: &str) -> ParsedEvent {
        AccessLogParser::new(ctx(APACHE_LOG))
            .parse_line(line)
            .expect("a non-blank line is an event")
    }

    fn parse_json(line: &str) -> ParsedEvent {
        AccessJsonParser::new(ctx(NGINX_JSON))
            .parse_line(line)
            .expect("a non-blank line is an event")
    }

    fn fixture(rel: &str) -> Vec<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn s(v: &str) -> FieldValue {
        FieldValue::Str(v.to_string())
    }

    fn field<'a>(ev: &'a ParsedEvent, key: &str) -> &'a FieldValue {
        ev.field(key)
            .unwrap_or_else(|| panic!("field {key} missing from {:?}", ev.fields))
    }

    fn keys(fields: &[(String, FieldValue)]) -> Vec<&str> {
        fields.iter().map(|(k, _)| k.as_str()).collect()
    }

    fn rfc3339(ev: &ParsedEvent) -> String {
        ev.timestamp.expect("timestamp").to_rfc3339()
    }

    /// Evaluate a `selection:` body (YAML lines indented by four spaces) against the event.
    fn selection_matches(selection: &str, ev: &ParsedEvent) -> bool {
        let yaml = format!(
            "title: t\nlogsource:\n  category: webserver\ndetection:\n  selection:\n{selection}  condition: selection\n"
        );
        sigma_rust::rule_from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("rule {yaml}: {e}"))
            .is_match(&ev.to_sigma_event())
    }

    // --- helpers: request line, unescaping, stem, time text -------------------------------

    #[test]
    fn request_line_follows_amendment_a10() {
        let some = |v: &str| Some(v.to_string());
        let rl =
            |method: Option<String>, target: Option<String>, version: Option<String>| RequestLine {
                method,
                target,
                version,
            };
        assert_eq!(
            parse_request_line("GET /index.php HTTP/1.1"),
            rl(some("GET"), some("/index.php"), some("HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("GET /"),
            rl(some("GET"), some("/"), None)
        );
        assert_eq!(
            parse_request_line("GET /a b HTTP/1.1"),
            rl(some("GET"), some("/a b"), some("HTTP/1.1"))
        );
        assert_eq!(parse_request_line("-"), RequestLine::default());
        assert_eq!(parse_request_line(""), RequestLine::default());
        assert_eq!(
            parse_request_line("GET /robots.txt HTTP/2.0").version,
            some("HTTP/2.0")
        );
        assert_eq!(parse_request_line("GET / HTTP/3").version, some("HTTP/3"));
        assert_eq!(
            parse_request_line("GET / HTTP/3.0").version,
            some("HTTP/3.0")
        );
        // a lowercase or hyphenated first token is not a method: it stays in the target
        assert_eq!(
            parse_request_line("get / HTTP/1.1"),
            rl(None, some("get /"), some("HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("M-SEARCH * HTTP/1.1"),
            rl(None, some("M-SEARCH *"), some("HTTP/1.1"))
        );
        assert_eq!(parse_request_line("GET"), rl(some("GET"), None, None));
        assert_eq!(
            parse_request_line("HTTP/1.1"),
            rl(None, None, some("HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("/index.php"),
            rl(None, some("/index.php"), None)
        );
        assert_eq!(
            parse_request_line("GET  /double  HTTP/1.1").target,
            some("/double")
        );
        assert_eq!(
            parse_request_line("GET /x HTTP/1.10"),
            rl(some("GET"), some("/x HTTP/1.10"), None)
        );
        assert_eq!(
            parse_request_line(r"\x16\x03\x01\x02"),
            rl(None, some(r"\x16\x03\x01\x02"), None)
        );
        assert_eq!(
            parse_request_line("PROPFIND /dav HTTP/1.1").method,
            some("PROPFIND")
        );
    }

    #[test]
    fn quoted_field_unescaping() {
        assert_eq!(
            unescape_quoted(r#"Mozilla/5.0 \"quoted\" agent"#),
            r#"Mozilla/5.0 "quoted" agent"#
        );
        assert_eq!(unescape_quoted(r"a\\b"), r"a\b");
        assert_eq!(
            unescape_quoted(r"\x16\x03"),
            r"\x16\x03",
            "other escapes stay verbatim"
        );
        assert_eq!(unescape_quoted(r"abc\"), r"abc\");
        assert!(matches!(unescape_quoted("plain"), Cow::Borrowed("plain")));
    }

    #[test]
    fn uri_stem_stops_at_the_first_question_mark() {
        assert_eq!(uri_stem("/"), "/");
        assert_eq!(uri_stem("/?a=1"), "/");
        assert_eq!(uri_stem("/index.php?x=1&y=2"), "/index.php");
        assert_eq!(uri_stem("/a?b?c"), "/a");
        assert_eq!(uri_stem("/no-query"), "/no-query");
    }

    #[test]
    fn time_text_helpers() {
        assert_eq!(
            slashes_to_dashes("2026/10/26 12:20:00"),
            "2026-10-26 12:20:00"
        );
        assert_eq!(
            slashes_to_dashes("26/Oct/2026:12:20:00 +0900"),
            "26/Oct/2026:12:20:00 +0900"
        );
        assert_eq!(slashes_to_dashes("short"), "short");
        assert!(looks_numeric("1792856132.869"));
        assert!(looks_numeric("1792856132"));
        assert!(!looks_numeric("1.2.3"));
        assert!(!looks_numeric("12:20:00"));
        assert!(!looks_numeric(".5"));
        assert!(parse_time_text("-", &jst()).is_none());
        assert!(parse_time_text("", &jst()).is_none());
        assert!(parse_time_text("yesterday", &jst()).is_none());
        assert!(parse_time_text("12:20:00", &jst()).is_none());
    }

    // --- text access log -------------------------------------------------------------------

    #[test]
    fn combined_line_has_the_full_taxonomy_in_order() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[0]);
        assert_eq!(ev.primary_logsource, "webserver");
        assert_eq!(rfc3339(&ev), "2026-10-26T12:00:00+09:00");
        assert!(ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(keys(&ev.fields[..7]), DETAILS_KEYS);
        assert_eq!(
            keys(&ev.fields[7..]),
            EXTRA_KEYS,
            "a plain combined line has neither ident nor extra"
        );
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.10"));
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri-query"), &s("/index.php"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(5123));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-user-agent"), &s(ua));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/index.php"));
        assert_eq!(field(&ev, "cs-uri"), &s("/index.php"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/1.1"));
        assert_eq!(field(&ev, "cs-username"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-host"), &FieldValue::Null);
        assert_eq!(field(&ev, "c-useragent"), &s(ua));
        assert_eq!(ev.hostname, None);
        assert_eq!(ev.raw, lines[0]);
    }

    #[test]
    fn referer_is_kept_when_present() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[1]);
        assert_eq!(field(&ev, "cs-referer"), &s("http://example.com/index.php"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/assets/app.css"));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(2048));
        assert_eq!(rfc3339(&ev), "2026-10-26T12:00:01+09:00");
    }

    #[test]
    fn poc_memory_pressure_line_splits_stem_and_query() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[2]);
        assert_eq!(field(&ev, "c-ip"), &s("198.51.100.77"));
        assert_eq!(field(&ev, "cs-method"), &s("POST"));
        assert_eq!(field(&ev, "cs-uri-query"), &s(POC_QUERY));
        assert_eq!(field(&ev, "cs-uri"), &s(POC_QUERY));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(149));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-user-agent"), &FieldValue::Null);
        assert_eq!(field(&ev, "c-useragent"), &FieldValue::Null);
    }

    #[test]
    fn ipv6_client_and_http2() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[6]);
        assert_eq!(field(&ev, "c-ip"), &s("2001:db8::10"));
        assert_eq!(
            field(&ev, "cs-host"),
            &FieldValue::Null,
            "an IPv6 client must not be taken for a vhost:port prefix"
        );
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/2.0"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/robots.txt"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(404));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(196));
        assert_eq!(field(&ev, "cs-user-agent"), &s("curl/8.5.0"));
        assert_eq!(rfc3339(&ev), "2026-10-26T12:10:00+09:00");
    }

    #[test]
    fn vhost_combined_line_sets_cs_host_and_unescapes_quotes() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[7]);
        assert_eq!(field(&ev, "cs-host"), &s("www.example.com:80"));
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.12"));
        assert_eq!(
            field(&ev, "cs-user-agent"),
            &s(r#"Mozilla/5.0 "quoted" agent"#)
        );
        assert_eq!(
            field(&ev, "c-useragent"),
            &s(r#"Mozilla/5.0 "quoted" agent"#)
        );
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(5123));
        assert_eq!(ev.hostname, None, "the vhost is cs-host, not the hostname");
        assert_eq!(rfc3339(&ev), "2026-10-26T12:11:00+09:00");
    }

    #[test]
    fn common_format_line_with_user_and_dash_bytes() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[8]);
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.13"));
        assert_eq!(field(&ev, "cs-username"), &s("frank"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(0));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-user-agent"), &FieldValue::Null);
        assert_eq!(field(&ev, "c-useragent"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/private/report.pdf"));
        assert_eq!(ev.field("extra"), None);
        assert_eq!(ev.field("ident"), None);
    }

    #[test]
    fn two_token_request_line() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[9]);
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri"), &s("/"));
        assert_eq!(field(&ev, "cs-uri-query"), &s("/"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert_eq!(field(&ev, "cs-version"), &FieldValue::Null);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(5));
    }

    #[test]
    fn dash_request_is_all_null_but_status_stays_int() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[10]);
        for key in [
            "cs-method",
            "cs-uri",
            "cs-uri-stem",
            "cs-uri-query",
            "cs-version",
        ] {
            assert_eq!(field(&ev, key), &FieldValue::Null, "{key}");
        }
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.16"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(408));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(0));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
    }

    #[test]
    fn space_inside_the_request_path() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[11]);
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri"), &s("/a b"));
        assert_eq!(field(&ev, "cs-uri-query"), &s("/a b"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/a b"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/1.1"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(404));
        assert_eq!(field(&ev, "cs-user-agent"), &s("curl/8.5.0"));
    }

    #[test]
    fn query_only_target_has_a_null_stem() {
        let ev = parse_text(
            r#"203.0.113.10 - - [26/Oct/2026:12:00:00 +0900] "GET ?x=1 HTTP/1.1" 200 1 "-" "-""#,
        );
        assert_eq!(field(&ev, "cs-uri"), &s("?x=1"));
        assert_eq!(field(&ev, "cs-uri-stem"), &FieldValue::Null);
    }

    #[test]
    fn apache_fixture_parses_every_line_as_an_entry() {
        let lines = fixture(APACHE_FIXTURE);
        assert_eq!(lines.len(), 12);
        let mut parser = AccessLogParser::new(ctx(APACHE_LOG));
        for line in &lines {
            assert!(matches_entry(line), "{line}");
            let ev = parser.parse_line(line).expect("event");
            assert!(ev.field("message").is_none(), "not a continuation: {line}");
            assert!(!ev.timestamp_inferred);
            assert!(ev.tz_explicit);
            assert!(matches!(field(&ev, "sc-status"), FieldValue::Int(_)));
            assert!(matches!(field(&ev, "sc-bytes"), FieldValue::Int(_)));
            for key in DETAILS_KEYS.iter().chain(EXTRA_KEYS.iter()) {
                assert!(ev.field(key).is_some(), "{key} missing in {line}");
            }
            assert_eq!(
                ev.tags,
                vec![
                    LogSourceTag::WEBSERVER,
                    LogSourceTag::APACHE_WEBSERVER,
                    LogSourceTag::APACHE_ACCESS
                ]
            );
        }
    }

    #[test]
    fn php2shell_text_fixture() {
        let lines = fixture(HONEYPOT_LOG);
        assert_eq!(lines.len(), 144);
        let mut parser = AccessLogParser::new(ctx(APACHE_LOG));
        let events: Vec<ParsedEvent> = lines.iter().filter_map(|l| parser.parse_line(l)).collect();
        assert_eq!(events.len(), 144);
        assert_eq!(rfc3339(&events[0]), "2026-10-24T15:35:32+00:00");
        assert_eq!(field(&events[0], "c-ip"), &s("15.204.59.70"));
        assert_eq!(field(&events[0], "cs-uri-query"), &s(POC_QUERY));
        assert_eq!(rfc3339(&events[143]), "2026-10-24T18:57:31+00:00");
        assert_eq!(field(&events[143], "c-ip"), &s("162.35.99.94"));
        assert_eq!(field(&events[143], "cs-uri-stem"), &s("/index.php"));
        let posts = events
            .iter()
            .filter(|e| e.field("cs-method") == Some(&s("POST")))
            .count();
        assert_eq!(posts, 143);
        let poc = events
            .iter()
            .filter(|e| {
                e.field_str("cs-uri-query")
                    .is_some_and(|q| q.contains("q0000000=v&q0000001=v"))
            })
            .count();
        assert_eq!(poc, 44);
        assert!(events.iter().all(|e| {
            e.field("cs-user-agent") == Some(&FieldValue::Null)
                && e.field("cs-referer") == Some(&FieldValue::Null)
                && e.field("sc-status") == Some(&FieldValue::Int(200))
        }));
    }

    #[test]
    fn trailing_fields_go_to_extra_and_ident_is_kept_when_set() {
        let ev = parse_text(
            r#"203.0.113.30 - - [26/Oct/2026:12:30:00 +0900] "GET /x HTTP/1.1" 200 12 "-" "curl/8.5.0" 0.512 "unix:/run/php.sock""#,
        );
        assert_eq!(field(&ev, "extra"), &s(r#"0.512 "unix:/run/php.sock""#));
        assert_eq!(field(&ev, "cs-user-agent"), &s("curl/8.5.0"));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(
            keys(&ev.fields[7..]),
            [
                "cs-uri-stem",
                "cs-uri",
                "cs-version",
                "cs-username",
                "cs-host",
                "c-useragent",
                "extra"
            ]
        );
        let ev = parse_text(
            r#"203.0.113.31 ident1 frank [26/Oct/2026:12:31:00 +0900] "GET / HTTP/1.1" 200 1"#,
        );
        assert_eq!(field(&ev, "ident"), &s("ident1"));
        assert_eq!(field(&ev, "cs-username"), &s("frank"));
        assert_eq!(ev.field("extra"), None);
        // a lone trailing quoted field does not pair up as referer + user agent
        let ev = parse_text(
            r#"203.0.113.32 - - [26/Oct/2026:12:32:00 +0900] "GET / HTTP/1.1" 200 1 "only-one""#,
        );
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-user-agent"), &FieldValue::Null);
        assert_eq!(field(&ev, "extra"), &s(r#""only-one""#));
    }

    #[test]
    fn escaped_backslash_and_quote_in_request_referer_and_agent() {
        let ev = parse_text(
            r#"203.0.113.33 - - [26/Oct/2026:12:33:00 +0900] "GET /a\\b HTTP/1.1" 200 1 "http://x/\"y\"" "ua\\1""#,
        );
        assert_eq!(field(&ev, "cs-uri"), &s(r"/a\b"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s(r"/a\b"));
        assert_eq!(field(&ev, "cs-referer"), &s(r#"http://x/"y""#));
        assert_eq!(field(&ev, "cs-user-agent"), &s(r"ua\1"));
        // nginx-style \xHH escapes are kept as written
        let ev = parse_text(
            r#"203.0.113.34 - - [26/Oct/2026:12:34:00 +0900] "\x16\x03\x01\x02\x00\x01\x00\x01\xFC\x03\x03" 400 157 "-" "-""#,
        );
        assert_eq!(field(&ev, "cs-method"), &FieldValue::Null);
        assert_eq!(
            field(&ev, "cs-uri"),
            &s(r"\x16\x03\x01\x02\x00\x01\x00\x01\xFC\x03\x03")
        );
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(400));
    }

    #[test]
    fn product_tags_follow_the_path() {
        let lines = fixture(APACHE_FIXTURE);
        let ev = parse_text(&lines[0]);
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::WEBSERVER,
                LogSourceTag::APACHE_WEBSERVER,
                LogSourceTag::APACHE_ACCESS
            ]
        );
        let ev = AccessLogParser::new(ctx("/var/log/nginx/access.log"))
            .parse_line(&lines[0])
            .expect("event");
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::WEBSERVER,
                LogSourceTag::NGINX_WEBSERVER,
                LogSourceTag::NGINX_ACCESS
            ]
        );
        let ev = AccessLogParser::new(ctx("/srv/logs/access.log"))
            .parse_line(&lines[0])
            .expect("event");
        assert_eq!(ev.tags, vec![LogSourceTag::WEBSERVER]);
        assert_eq!(ev.primary_logsource, "webserver");
        // the JSON parser tags the same way
        let ev = AccessJsonParser::new(ctx("/var/log/httpd/access.json"))
            .parse_line(r#"{"method":"GET","status":200}"#)
            .expect("event");
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::WEBSERVER,
                LogSourceTag::APACHE_WEBSERVER,
                LogSourceTag::APACHE_ACCESS
            ]
        );
        assert_eq!(ev.primary_logsource, "webserver");
    }

    #[test]
    fn hostname_hint_and_extra_tags_come_from_the_context() {
        let lines = fixture(APACHE_FIXTURE);
        let mut c = ctx(APACHE_LOG);
        c.hostname_hint = Some("web01".to_string());
        c.extra_tags = vec![LogSourceTag::LINUX_SYSLOG];
        let mut parser = AccessLogParser::new(c);
        let ev = parser.parse_line(&lines[7]).expect("event");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert_eq!(field(&ev, "cs-host"), &s("www.example.com:80"));
        assert!(ev.tags.contains(&LogSourceTag::LINUX_SYSLOG));
        assert!(selection_matches("    hostname: web01\n", &ev));
        let cont = parser.parse_line("junk").expect("event");
        assert_eq!(cont.hostname.as_deref(), Some("web01"));
        assert!(cont.tags.contains(&LogSourceTag::LINUX_SYSLOG));
    }

    #[test]
    fn continuation_and_blank_lines() {
        let lines = fixture(APACHE_FIXTURE);
        let mut parser = AccessLogParser::new(ctx(APACHE_LOG));
        assert!(parser.parse_line("").is_none());
        assert!(parser.parse_line("   \t").is_none());
        let first = parser.parse_line("sh: 1: wget: not found").expect("event");
        assert_eq!(first.timestamp, None);
        assert!(!first.timestamp_inferred);
        assert_eq!(
            first.fields,
            vec![("message".to_string(), s("sh: 1: wget: not found"))]
        );
        assert_eq!(first.primary_logsource, "webserver");
        assert_eq!(
            first.tags,
            vec![
                LogSourceTag::WEBSERVER,
                LogSourceTag::APACHE_WEBSERVER,
                LogSourceTag::APACHE_ACCESS
            ]
        );
        parser.parse_line(&lines[0]).expect("event");
        let cont = parser.parse_line("  indented continuation").expect("event");
        assert_eq!(rfc3339(&cont), "2026-10-26T12:00:00+09:00");
        assert!(cont.timestamp_inferred);
        assert!(!cont.tz_explicit);
        assert_eq!(cont.field("c-ip"), None);
        assert_eq!(field(&cont, "message"), &s("  indented continuation"));
        assert!(!matches_entry("  indented continuation"));
        assert!(selection_matches(
            "    message|contains: continuation\n",
            &cont
        ));
    }

    #[test]
    fn malformed_time_borrows_the_previous_timestamp() {
        let lines = fixture(APACHE_FIXTURE);
        let bad = r#"203.0.113.10 - - [not a time] "GET / HTTP/1.1" 200 1 "-" "-""#;
        let mut parser = AccessLogParser::new(ctx(APACHE_LOG));
        let ev = parser.parse_line(bad).expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.10"));
        parser.parse_line(&lines[0]).expect("event");
        let ev = parser.parse_line(bad).expect("event");
        assert_eq!(rfc3339(&ev), "2026-10-26T12:00:00+09:00");
        assert!(ev.timestamp_inferred);
        assert!(!ev.tz_explicit);
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
    }

    #[test]
    fn iso_and_epoch_times_inside_the_brackets_are_accepted() {
        let ev = parse_text(
            r#"203.0.113.10 - - [2026-10-26T12:00:00+09:00] "GET / HTTP/1.1" 200 1 "-" "-""#,
        );
        assert_eq!(rfc3339(&ev), "2026-10-26T12:00:00+09:00");
        assert!(ev.tz_explicit);
        let ev =
            parse_text(r#"203.0.113.10 - - [2026-10-26 03:00:00] "GET / HTTP/1.1" 200 1 "-" "-""#);
        assert_eq!(
            rfc3339(&ev),
            "2026-10-26T03:00:00+09:00",
            "a naive time takes the -z assumption"
        );
        assert!(!ev.tz_explicit);
        let ev = parse_text(r#"203.0.113.10 - - [1792856132] "GET / HTTP/1.1" 200 1 "-" "-""#);
        assert_eq!(rfc3339(&ev), "2026-10-24T15:35:32+00:00");
        assert!(ev.tz_explicit);
    }

    #[test]
    fn matches_entry_shapes() {
        for line in fixture(APACHE_FIXTURE) {
            assert!(matches_entry(&line), "{line}");
        }
        assert!(matches_entry(
            r#"203.0.113.30 - - [26/Oct/2026:12:30:00 +0900] "GET /x HTTP/1.1" 200 12 "-" "curl/8.5.0" 0.512"#
        ));
        assert!(matches_entry(
            r#"203.0.113.30 - - [26/Oct/2026:12:30:00 +0900] "GET /x HTTP/1.1" 200 12"#
        ));
        assert!(!matches_entry(
            "Oct 26 17:39:01 host sshd[1]: Accepted password for root"
        ));
        assert!(!matches_entry(r#"{"method":"GET","status":200}"#));
        assert!(!matches_entry(
            "[Sat Oct 24 15:35:39.379473 2026] [core:notice] [pid 1:tid 1] AH00094: Command line"
        ));
        assert!(!matches_entry(""));
        assert!(!matches_entry("sh: 1: wget: not found"));
        assert!(
            !matches_entry(
                r#"203.0.113.10 - - [26/Oct/2026:12:00:00 +0900] "GET / HTTP/1.1" 20 5"#
            ),
            "the status has three digits"
        );
    }

    #[test]
    fn text_bytes_overflow_is_null_not_a_string() {
        let ev = parse_text(
            r#"203.0.113.10 - - [26/Oct/2026:12:00:00 +0900] "GET / HTTP/1.1" 200 99999999999999999999 "-" "-""#,
        );
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Null);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
    }

    // --- Sigma rules against both parsers --------------------------------------------------

    #[test]
    fn regeorg_filter_shape_matches_requests_without_referer_and_user_agent() {
        let lines = fixture(APACHE_FIXTURE);
        let sel = "    cs-method: POST\n    cs-referer: null\n    cs-user-agent: null\n";
        assert!(selection_matches(sel, &parse_text(&lines[2])));
        assert!(selection_matches(sel, &parse_text(&lines[3])));
        assert!(
            !selection_matches(sel, &parse_text(&lines[0])),
            "GET with a user agent"
        );
        let honeypot = fixture(HONEYPOT_JSON);
        assert!(selection_matches(sel, &parse_json(&honeypot[0])));
        let nginx = fixture(NGINX_FIXTURE);
        assert!(
            selection_matches(sel, &parse_json(&nginx[0])),
            "JSON \"-\" referer and user agent are Null"
        );
        assert!(
            !selection_matches(sel, &parse_json(&nginx[1])),
            "GET with a user agent"
        );
    }

    #[test]
    fn status_rules_compare_numbers_for_text_and_json() {
        let lines = fixture(APACHE_FIXTURE);
        let text404 = parse_text(&lines[6]);
        let text200 = parse_text(&lines[0]);
        let text500 = parse_text(&lines[5]);
        let json404 = parse_json(r#"{"method":"GET","uri":"/x","status":"404"}"#);
        let json200 = parse_json(r#"{"method":"GET","uri":"/x","status":200}"#);
        for sel in ["    sc-status: 404\n", "    sc-status|gte: 400\n"] {
            assert!(selection_matches(sel, &text404), "{sel}");
            assert!(selection_matches(sel, &json404), "{sel}");
            assert!(!selection_matches(sel, &text200), "{sel}");
            assert!(!selection_matches(sel, &json200), "{sel}");
        }
        assert!(selection_matches("    sc-status|gte: 400\n", &text500));
        assert!(!selection_matches("    sc-status: 404\n", &text500));
        assert!(selection_matches("    sc-status|lt: 300\n", &json200));
        assert!(
            selection_matches("    sc-bytes: 0\n", &parse_text(&lines[8])),
            "'-' bytes are Int(0)"
        );
        assert!(selection_matches(
            "    sc-status: 408\n    cs-method: null\n",
            &parse_text(&lines[10])
        ));
    }

    #[test]
    fn shipped_php2shell_rule_fires_on_text_and_json_poc_requests() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules/iwatobi/web/webserver/web_php2shell_memory_pressure_request.yml");
        let yaml = std::fs::read_to_string(&path).expect("shipped rule");
        let rule = sigma_rust::rule_from_yaml(&yaml).expect("shipped rule parses");
        let lines = fixture(APACHE_FIXTURE);
        assert!(rule.is_match(&parse_text(&lines[2]).to_sigma_event()));
        assert!(!rule.is_match(&parse_text(&lines[3]).to_sigma_event()));
        let honeypot = fixture(HONEYPOT_JSON);
        assert!(rule.is_match(&parse_json(&honeypot[0]).to_sigma_event()));
        assert!(!rule.is_match(&parse_json(&honeypot[1]).to_sigma_event()));
        let nginx = fixture(NGINX_FIXTURE);
        assert!(rule.is_match(&parse_json(&nginx[0]).to_sigma_event()));
        let mut parser = AccessJsonParser::new(ctx(NGINX_JSON));
        let hits = honeypot
            .iter()
            .filter(|l| {
                parser
                    .parse_line(l)
                    .is_some_and(|ev| rule.is_match(&ev.to_sigma_event()))
            })
            .count();
        assert_eq!(hits, 44);
        let mut parser = AccessLogParser::new(ctx(APACHE_LOG));
        let hits = fixture(HONEYPOT_LOG)
            .iter()
            .filter(|l| {
                parser
                    .parse_line(l)
                    .is_some_and(|ev| rule.is_match(&ev.to_sigma_event()))
            })
            .count();
        assert_eq!(hits, 44);
    }

    #[test]
    fn other_taxonomy_selections() {
        let lines = fixture(APACHE_FIXTURE);
        let post_index =
            "    cs-method: POST\n    cs-uri-stem:\n      - '/'\n      - '/index.php'\n";
        assert!(selection_matches(post_index, &parse_text(&lines[3])));
        assert!(selection_matches(post_index, &parse_text(&lines[5])));
        assert!(
            selection_matches(post_index, &parse_text(&lines[2])),
            "the stem of /?q... is /"
        );
        assert!(!selection_matches(post_index, &parse_text(&lines[0])));
        assert!(selection_matches(
            "    cs-host: 'www.example.com:80'\n",
            &parse_text(&lines[7])
        ));
        assert!(selection_matches(
            "    cs-user-agent|contains: '\"quoted\"'\n",
            &parse_text(&lines[7])
        ));
        assert!(selection_matches(
            "    c-ip|cidr: '203.0.113.0/24'\n",
            &parse_text(&lines[0])
        ));
        assert!(!selection_matches(
            "    c-ip|cidr: '203.0.113.0/24'\n",
            &parse_text(&lines[2])
        ));
        assert!(selection_matches(
            "    cs-version: 'HTTP/2.0'\n",
            &parse_text(&lines[6])
        ));
        assert!(selection_matches(
            "    cs-username: frank\n",
            &parse_text(&lines[8])
        ));
        assert!(selection_matches(
            "    cs-uri-query|contains: 'a b'\n",
            &parse_text(&lines[11])
        ));
        assert!(selection_matches(
            "    cs-uri-query|contains: 'q0000000=v&q0000001=v'\n",
            &parse_text(&lines[2])
        ));
    }

    // --- JSON access log -------------------------------------------------------------------

    #[test]
    fn honeypot_first_record_exact_values() {
        let honeypot = fixture(HONEYPOT_JSON);
        let ev = parse_json(&honeypot[0]);
        assert_eq!(rfc3339(&ev), "2026-10-24T15:35:32.869295+00:00");
        assert!(ev.tz_explicit);
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.primary_logsource, "webserver");
        assert_eq!(field(&ev, "c-ip"), &s("15.204.59.70"));
        assert_eq!(field(&ev, "cs-method"), &s("POST"));
        assert_eq!(field(&ev, "cs-uri-query"), &s(POC_QUERY));
        assert_eq!(field(&ev, "cs-uri"), &s(POC_QUERY));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(149));
        assert_eq!(field(&ev, "cs-user-agent"), &FieldValue::Null);
        assert_eq!(field(&ev, "c-useragent"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-host"), &s("198.51.100.11:80"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/1.1"));
        assert_eq!(field(&ev, "cs-username"), &FieldValue::Null);
        assert_eq!(keys(&ev.fields[..7]), DETAILS_KEYS);
        // the original keys follow, in document order, with their original types
        let extra = keys(&ev.fields[7..]);
        assert_eq!(&extra[..6], &EXTRA_KEYS);
        assert_eq!(
            &extra[6..],
            &[
                "ts",
                "pid",
                "tid",
                "keepalive",
                "peerIp",
                "peerPort",
                "localPort",
                "host",
                "method",
                "uri",
                "proto",
                "status",
                "respBytes",
                "durationUs",
                "reqId",
                "setCookie"
            ]
        );
        assert_eq!(field(&ev, "ts"), &s("2026-10-24T15:35:32.869295Z"));
        assert_eq!(field(&ev, "pid"), &FieldValue::Int(31));
        assert_eq!(field(&ev, "tid"), &FieldValue::Int(126_070_389_337_088));
        assert_eq!(field(&ev, "keepalive"), &FieldValue::Int(0));
        assert_eq!(field(&ev, "peerPort"), &FieldValue::Int(54952));
        assert_eq!(field(&ev, "status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "durationUs"), &FieldValue::Int(516_788));
        assert_eq!(
            field(&ev, "reqId"),
            &s("-"),
            "original keys keep their raw strings"
        );
        assert_eq!(field(&ev, "setCookie"), &s("-"));
        assert_eq!(ev.raw, honeypot[0]);
    }

    #[test]
    fn honeypot_nested_object_is_flattened() {
        let honeypot = fixture(HONEYPOT_JSON);
        let with_redaction: Vec<&String> = honeypot
            .iter()
            .filter(|l| l.contains("setCookieRedaction"))
            .collect();
        assert_eq!(with_redaction.len(), 37);
        let ev = parse_json(with_redaction[0]);
        assert_eq!(rfc3339(&ev), "2026-10-24T15:35:34.205642+00:00");
        assert_eq!(
            field(&ev, "setCookieRedaction.decodedValueBytes"),
            &FieldValue::Int(819_200)
        );
        assert_eq!(
            field(&ev, "setCookieRedaction.encodedValueBytes"),
            &FieldValue::Int(1_662_470)
        );
        assert_eq!(
            field(&ev, "setCookieRedaction.decodedValueSha256"),
            &s("33b9cad1f5f7d63986d15d58382055e895bde554cc562b6292fc51afc68cea17")
        );
        assert_eq!(
            ev.field("setCookieRedaction"),
            None,
            "the parent object itself is not a field"
        );
        assert_eq!(
            field(&ev, "setCookie"),
            &s("PHPSESSID=[REDACTED_MEMORY_DISCLOSURE]; path=/")
        );
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(1599));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert!(selection_matches(
            "    setCookieRedaction.decodedValueBytes|gte: 800000\n",
            &ev
        ));
        assert!(selection_matches(
            "    setCookie|startswith: 'PHPSESSID='\n",
            &ev
        ));
    }

    #[test]
    fn honeypot_fixture_parses_every_record() {
        let honeypot = fixture(HONEYPOT_JSON);
        assert_eq!(honeypot.len(), 144);
        let mut parser = AccessJsonParser::new(ctx("/var/log/apache2/access.jsonl"));
        let mut redacted = 0;
        let mut gets = 0;
        let mut host11 = 0;
        for line in &honeypot {
            assert!(matches_json_entry(line), "{line}");
            let ev = parser.parse_line(line).expect("event");
            assert!(ev.field("message").is_none(), "not a continuation: {line}");
            assert!(ev.timestamp.is_some());
            assert!(ev.tz_explicit);
            assert!(!ev.timestamp_inferred);
            assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
            assert!(matches!(field(&ev, "sc-bytes"), FieldValue::Int(_)));
            assert!(matches!(field(&ev, "c-ip"), FieldValue::Str(_)));
            // four honeypot hosts, all TEST-NET-2 aliases
            assert!(
                ev.field_str("cs-host")
                    .is_some_and(|h| h.starts_with("198.51.100.")),
                "{line}"
            );
            assert_eq!(
                ev.tags,
                vec![
                    LogSourceTag::WEBSERVER,
                    LogSourceTag::APACHE_WEBSERVER,
                    LogSourceTag::APACHE_ACCESS
                ]
            );
            if ev.field("setCookieRedaction.decodedValueBytes").is_some() {
                redacted += 1;
            }
            if ev.field("cs-method") == Some(&s("GET")) {
                gets += 1;
            }
            if ev.field_str("cs-host") == Some("198.51.100.11:80") {
                host11 += 1;
            }
        }
        assert_eq!(redacted, 37);
        assert_eq!(gets, 1);
        assert_eq!(host11, 29);
    }

    #[test]
    fn nginx_json_time_local_and_request_line() {
        let nginx = fixture(NGINX_FIXTURE);
        let ev = parse_json(&nginx[0]);
        assert_eq!(rfc3339(&ev), "2026-10-26T12:20:00+09:00");
        assert!(ev.tz_explicit);
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.20"));
        assert_eq!(field(&ev, "cs-method"), &s("POST"));
        assert_eq!(field(&ev, "cs-uri-query"), &s(POC_QUERY));
        assert_eq!(field(&ev, "cs-uri"), &s(POC_QUERY));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/1.1"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(149));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-user-agent"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-host"), &FieldValue::Null);
        assert_eq!(field(&ev, "http_referer"), &s("-"));
        assert_eq!(field(&ev, "http_user_agent"), &s("-"));
        assert_eq!(field(&ev, "request_time"), &FieldValue::Float(0.512));
        assert_eq!(
            field(&ev, "request"),
            &s("POST /?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v HTTP/1.1")
        );
        assert_eq!(
            ev.tags,
            vec![
                LogSourceTag::WEBSERVER,
                LogSourceTag::NGINX_WEBSERVER,
                LogSourceTag::NGINX_ACCESS
            ]
        );
    }

    #[test]
    fn nginx_json_quoted_numbers_become_int_on_taxonomy_keys_only() {
        let nginx = fixture(NGINX_FIXTURE);
        let ev = parse_json(&nginx[1]);
        assert_eq!(rfc3339(&ev), "2026-10-26T12:21:00+09:00");
        assert!(ev.tz_explicit);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "status"), &s("200"));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(5123));
        assert_eq!(field(&ev, "body_bytes_sent"), &s("5123"));
        assert_eq!(field(&ev, "c-ip"), &s("203.0.113.21"));
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri"), &s("/index.php"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/index.php"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/1.1"));
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        assert_eq!(field(&ev, "cs-user-agent"), &s(ua));
        assert_eq!(field(&ev, "c-useragent"), &s(ua));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-host"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-username"), &FieldValue::Null);
    }

    #[test]
    fn nginx_json_at_timestamp_and_nested_upstream() {
        let nginx = fixture(NGINX_FIXTURE);
        let ev = parse_json(&nginx[2]);
        assert_eq!(rfc3339(&ev), "2026-10-26T03:22:00.250+00:00");
        assert!(ev.tz_explicit);
        assert_eq!(field(&ev, "c-ip"), &s("2001:db8::20"));
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri"), &s("/robots.txt"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/2.0"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(404));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(196));
        assert_eq!(field(&ev, "cs-user-agent"), &s("curl/8.5.0"));
        assert_eq!(
            field(&ev, "upstream.addr"),
            &s("unix:/run/php/php8.3-fpm.sock")
        );
        assert_eq!(
            field(&ev, "upstream.response_time"),
            &FieldValue::Float(0.004)
        );
        assert_eq!(ev.field("upstream"), None);
        assert!(selection_matches(
            "    upstream.addr|startswith: 'unix:'\n",
            &ev
        ));
        assert!(selection_matches("    sc-status|gte: 400\n", &ev));
    }

    #[test]
    fn json_timestamp_variants() {
        let ts = |line: &str| {
            let ev = parse_json(line);
            (rfc3339(&ev), ev.tz_explicit)
        };
        let exact = |t: &str, explicit: bool| (t.to_string(), explicit);
        assert_eq!(
            ts(r#"{"ts":1792856132,"method":"GET","status":200}"#),
            exact("2026-10-24T15:35:32+00:00", true)
        );
        assert_eq!(
            ts(r#"{"ts":1792856132.869,"method":"GET","status":200}"#),
            exact("2026-10-24T15:35:32.869+00:00", true)
        );
        assert_eq!(
            ts(r#"{"timestamp_ms":1792856132869,"method":"GET","status":200}"#),
            exact("2026-10-24T15:35:32.869+00:00", true)
        );
        assert_eq!(
            ts(r#"{"msec":"1792856132.869","method":"GET","status":200}"#),
            exact("2026-10-24T15:35:32.869+00:00", true)
        );
        assert_eq!(
            ts(r#"{"time":"2026-10-26 12:20:00","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00+09:00", false)
        );
        assert_eq!(
            ts(r#"{"time":"2026-10-26T12:20:00.5","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00.500+09:00", false)
        );
        assert_eq!(
            ts(r#"{"datetime":"2026/10/26 12:20:00","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00+09:00", false)
        );
        assert_eq!(
            ts(r#"{"time":"2026-10-26 12:20:00 +0100","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00+01:00", true)
        );
        assert_eq!(
            ts(r#"{"date":"2026-10-26","time":"12:20:00","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00+09:00", false)
        );
        assert_eq!(
            ts(r#"{"date":"2026-10-26","time":"12:20:00Z","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00+00:00", true)
        );
        assert_eq!(
            ts(r#"{"date":"2026/10/26","method":"GET","status":200}"#),
            exact("2026-10-26T00:00:00+09:00", false)
        );
        assert_eq!(
            ts(
                r#"{"time":"12:20:00","timestamp":"2026-10-26T12:20:00+09:00","method":"GET","status":200}"#
            ),
            exact("2026-10-26T12:20:00+09:00", true),
            "an unparsable earlier key falls through to the next one"
        );
        assert_eq!(
            ts(r#"{"time_local":"[26/Oct/2026:12:20:00 +0900]","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00+09:00", true)
        );
        assert_eq!(
            ts(r#"{"time":"26/Oct/2026:12:20:00 -0500","method":"GET","status":200}"#),
            exact("2026-10-26T12:20:00-05:00", true)
        );
        assert_eq!(
            ts(r#"{"Time":"2026-10-24T15:35:32.869295Z","method":"GET","status":200}"#),
            exact("2026-10-24T15:35:32.869295+00:00", true),
            "time keys are case-insensitive"
        );
    }

    #[test]
    fn json_without_a_timestamp_borrows_the_previous_one() {
        let mut parser = AccessJsonParser::new(ctx(NGINX_JSON));
        let ev = parser
            .parse_line(r#"{"method":"GET","status":200}"#)
            .expect("event");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        parser
            .parse_line(r#"{"ts":"2026-10-24T15:35:32Z","method":"GET","status":200}"#)
            .expect("event");
        let ev = parser
            .parse_line(r#"{"method":"POST","status":500,"time":"-"}"#)
            .expect("event");
        assert_eq!(rfc3339(&ev), "2026-10-24T15:35:32+00:00");
        assert!(ev.timestamp_inferred);
        assert!(!ev.tz_explicit);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(500));
        let cont = parser.parse_line("not json at all").expect("event");
        assert_eq!(rfc3339(&cont), "2026-10-24T15:35:32+00:00");
        assert!(cont.timestamp_inferred);
        assert_eq!(
            cont.fields,
            vec![("message".to_string(), s("not json at all"))]
        );
        assert_eq!(
            cont.tags,
            vec![
                LogSourceTag::WEBSERVER,
                LogSourceTag::NGINX_WEBSERVER,
                LogSourceTag::NGINX_ACCESS
            ]
        );
        assert!(parser.parse_line("").is_none());
        assert!(parser.parse_line("  ").is_none());
    }

    #[test]
    fn json_missing_aliases_are_null_but_present() {
        let ev = parse_json(r#"{"foo":"bar","n":1}"#);
        assert_eq!(keys(&ev.fields[..7]), DETAILS_KEYS);
        for key in DETAILS_KEYS.iter().chain(EXTRA_KEYS.iter()) {
            assert_eq!(field(&ev, key), &FieldValue::Null, "{key}");
        }
        assert_eq!(
            keys(&ev.fields[7..]),
            [
                "cs-uri-stem",
                "cs-uri",
                "cs-version",
                "cs-username",
                "cs-host",
                "c-useragent",
                "foo",
                "n"
            ]
        );
        assert_eq!(field(&ev, "n"), &FieldValue::Int(1));
        assert!(selection_matches(
            "    cs-referer: null\n    sc-status: null\n    sc-bytes: null\n",
            &ev
        ));
        assert!(!selection_matches("    sc-status|gte: 400\n", &ev));
        assert!(!selection_matches("    cs-method: GET\n", &ev));
    }

    #[test]
    fn json_aliases_are_case_insensitive_and_the_first_with_a_value_wins() {
        let ev = parse_json(
            r#"{"Method":"get","STATUS":"301","Remote_Addr":"-","Client_IP":"10.1.2.3","Http_Referer":"","Referrer":"http://r/","User_Agent":null,"UA":"x","Body_Bytes_Sent":"","Host":"h","Remote_User":"-","auth_user":"bob"}"#,
        );
        assert_eq!(field(&ev, "cs-method"), &s("get"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(301));
        assert_eq!(
            field(&ev, "c-ip"),
            &s("10.1.2.3"),
            "a '-' alias is skipped in favour of a later alias with a value"
        );
        assert_eq!(field(&ev, "cs-referer"), &s("http://r/"));
        assert_eq!(field(&ev, "cs-user-agent"), &s("x"));
        assert_eq!(field(&ev, "c-useragent"), &s("x"));
        assert_eq!(
            field(&ev, "sc-bytes"),
            &FieldValue::Int(0),
            "an empty byte count means nothing was sent"
        );
        assert_eq!(field(&ev, "cs-host"), &s("h"));
        assert_eq!(field(&ev, "cs-username"), &s("bob"));
        assert_eq!(
            field(&ev, "Method"),
            &s("get"),
            "original keys keep their spelling and type"
        );
        assert_eq!(field(&ev, "STATUS"), &s("301"));
        assert_eq!(field(&ev, "Remote_Addr"), &s("-"));
        assert_eq!(field(&ev, "User_Agent"), &FieldValue::Null);
    }

    #[test]
    fn json_request_line_fills_what_dedicated_keys_lack() {
        let ev = parse_json(r#"{"request":"GET /a?b=1 HTTP/1.1","uri":"/rewritten","status":200}"#);
        assert_eq!(
            field(&ev, "cs-uri"),
            &s("/rewritten"),
            "a dedicated uri key wins over the request line"
        );
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/1.1"));
        let ev = parse_json(r#"{"request":"-","method":"POST","status":200}"#);
        assert_eq!(field(&ev, "cs-method"), &s("POST"));
        assert_eq!(field(&ev, "cs-uri"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-version"), &FieldValue::Null);
        let ev = parse_json(r#"{"request":"GET /a b HTTP/1.1","status":200}"#);
        assert_eq!(field(&ev, "cs-uri"), &s("/a b"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/a b"));
        let ev = parse_json(r#"{"request":"GET /","status":200}"#);
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri"), &s("/"));
        assert_eq!(field(&ev, "cs-version"), &FieldValue::Null);
        let ev = parse_json(
            r#"{"request":"GET /x HTTP/1.1","method":"HEAD","proto":"HTTP/2.0","status":200}"#,
        );
        assert_eq!(field(&ev, "cs-method"), &s("HEAD"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/2.0"));
        assert_eq!(field(&ev, "cs-uri"), &s("/x"));
    }

    #[test]
    fn json_separate_query_string_is_appended_to_the_target() {
        let ev = parse_json(
            r#"{"method":"GET","uri":"/index.php","args":"q0000000=v&q0000001=v","status":200}"#,
        );
        assert_eq!(
            field(&ev, "cs-uri-query"),
            &s("/index.php?q0000000=v&q0000001=v")
        );
        assert_eq!(field(&ev, "cs-uri"), &s("/index.php?q0000000=v&q0000001=v"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/index.php"));
        assert_eq!(field(&ev, "args"), &s("q0000000=v&q0000001=v"));
        let ev =
            parse_json(r#"{"method":"GET","uri":"/x?already=1","args":"ignored=1","status":200}"#);
        assert_eq!(field(&ev, "cs-uri"), &s("/x?already=1"));
        let ev = parse_json(r#"{"method":"GET","uri":"/x","args":"-","status":200}"#);
        assert_eq!(field(&ev, "cs-uri"), &s("/x"));
        let ev = parse_json(r#"{"method":"GET","uri":"/x","query":"?a=1","status":200}"#);
        assert_eq!(field(&ev, "cs-uri"), &s("/x?a=1"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/x"));
    }

    #[test]
    fn json_nested_request_object_caddy_style() {
        let line = r#"{"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"]}},"bytes_read":0,"user_id":"","duration":0.000204744,"size":12,"status":200}"#;
        assert!(matches_json_entry(line));
        let ev = parse_json(line);
        assert_eq!(rfc3339(&ev), "2022-03-09T21:30:01.524102+00:00");
        assert!(ev.tz_explicit);
        assert_eq!(field(&ev, "c-ip"), &s("127.0.0.1"));
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "cs-uri"), &s("/"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/2.0"));
        assert_eq!(field(&ev, "cs-host"), &s("localhost"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(12));
        assert_eq!(field(&ev, "cs-user-agent"), &FieldValue::Null);
        assert_eq!(field(&ev, "cs-username"), &FieldValue::Null);
        assert_eq!(
            field(&ev, "request.headers.User-Agent"),
            &s(r#"["curl/7.82.0"]"#),
            "arrays are kept as JSON text"
        );
        assert_eq!(field(&ev, "request.remote_port"), &s("41342"));
        assert_eq!(field(&ev, "duration"), &FieldValue::Float(0.000204744));
        assert_eq!(field(&ev, "bytes_read"), &FieldValue::Int(0));
        assert_eq!(field(&ev, "ts"), &FieldValue::Float(1646861401.5241024));
        assert_eq!(field(&ev, "user_id"), &s(""));
        assert_eq!(ev.field("request"), None);
    }

    #[test]
    fn json_non_object_and_invalid_lines_are_continuations() {
        let mut parser = AccessJsonParser::new(ctx(NGINX_JSON));
        for line in [
            "[1,2]",
            "\"string\"",
            "42",
            "{not json}",
            "{\"a\":1",
            "plain text",
            "{\"a\":1} trailing",
        ] {
            let ev = parser.parse_line(line).expect("event");
            assert_eq!(ev.fields, vec![("message".to_string(), s(line))], "{line}");
            assert!(!matches_json_entry(line), "{line}");
        }
        // a JSON object that is not access-shaped is still an entry inside an access JSON file
        let ev = parser.parse_line(r#"{"a":1}"#).expect("event");
        assert_eq!(field(&ev, "a"), &FieldValue::Int(1));
        assert_eq!(field(&ev, "cs-method"), &FieldValue::Null);
        assert!(!matches_json_entry(r#"{"a":1}"#));
    }

    #[test]
    fn json_arrays_bools_nulls_and_empty_objects() {
        let ev = parse_json(
            r#"{"method":"GET","status":200,"tags":["a",1,true,null],"keepalive":true,"nothing":null,"upstream":{},"deep":{"a":{"b":{"c":"d"}}},"neg":-5,"big":18446744073709551615,"whole":3.0,"frac":2.5,"list_of_objects":[{"k":"v"}]}"#,
        );
        assert_eq!(field(&ev, "tags"), &s(r#"["a",1,true,null]"#));
        assert_eq!(field(&ev, "keepalive"), &FieldValue::Bool(true));
        assert_eq!(field(&ev, "nothing"), &FieldValue::Null);
        assert_eq!(field(&ev, "upstream"), &FieldValue::Null);
        assert_eq!(field(&ev, "deep.a.b.c"), &s("d"));
        assert_eq!(field(&ev, "neg"), &FieldValue::Int(-5));
        assert_eq!(
            field(&ev, "big"),
            &FieldValue::Float(18_446_744_073_709_551_615.0)
        );
        // A whole float stays a float: a field's type must not depend on its value.
        assert_eq!(field(&ev, "whole"), &FieldValue::Float(3.0));
        assert_eq!(field(&ev, "frac"), &FieldValue::Float(2.5));
        assert_eq!(field(&ev, "list_of_objects"), &s(r#"[{"k":"v"}]"#));
        assert!(selection_matches(
            "    keepalive: true\n    nothing: null\n    deep.a.b.c: d\n    neg|lt: 0\n",
            &ev
        ));
    }

    #[test]
    fn matches_json_entry_shapes() {
        assert!(matches_json_entry(r#"{"method":"GET","status":200}"#));
        assert!(matches_json_entry(r#"{"request":"GET / HTTP/1.1"}"#));
        assert!(matches_json_entry(
            r#"  {"request_method":"GET","sc_status":"200"}  "#
        ));
        assert!(matches_json_entry(
            r#"{"request":{"method":"GET","uri":"/"},"status":200}"#
        ));
        assert!(matches_json_entry(r#"{"verb":"GET","response_code":null}"#));
        for line in fixture(NGINX_FIXTURE) {
            assert!(matches_json_entry(&line), "{line}");
        }
        assert!(!matches_json_entry(r#"{"method":"GET"}"#), "no status");
        assert!(!matches_json_entry(r#"{"status":200}"#), "no method");
        assert!(!matches_json_entry(r#"{"foo":1}"#));
        assert!(!matches_json_entry("[1,2]"));
        assert!(!matches_json_entry("not json"));
        assert!(!matches_json_entry(""));
        assert!(!matches_json_entry(
            r#"203.0.113.10 - - [26/Oct/2026:12:00:00 +0900] "GET / HTTP/1.1" 200 5"#
        ));
        assert!(!matches_json_entry(
            r#"{"message":"PHP Warning: {\"method\":\"GET\",\"status\":200}"}"#
        ));
    }

    #[test]
    fn json_literal_taxonomy_keys_are_coerced_and_not_duplicated() {
        let ev = parse_json(
            r#"{"c-ip":"10.0.0.1","cs-method":"GET","cs-uri":"/x?y=1","sc-status":"404","sc-bytes":"12","cs-user-agent":"ua","time":"2026-10-26T00:00:00Z"}"#,
        );
        assert_eq!(field(&ev, "c-ip"), &s("10.0.0.1"));
        assert_eq!(field(&ev, "cs-method"), &s("GET"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(404));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(12));
        assert_eq!(field(&ev, "cs-uri-query"), &s("/x?y=1"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/x"));
        assert_eq!(field(&ev, "c-useragent"), &s("ua"));
        assert_eq!(
            ev.fields.iter().filter(|(k, _)| k == "sc-status").count(),
            1
        );
        assert_eq!(ev.fields.len(), 14, "13 taxonomy keys + time");
        assert_eq!(rfc3339(&ev), "2026-10-26T00:00:00+00:00");
        assert!(selection_matches("    sc-status|gte: 400\n", &ev));
    }

    #[test]
    fn json_numeric_edge_cases() {
        let ev = parse_json(r#"{"method":"GET","status":"abc","bytes":"-"}"#);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Null);
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(0));
        let ev = parse_json(r#"{"method":"GET","status":200.0,"bytes":null}"#);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(
            field(&ev, "sc-bytes"),
            &FieldValue::Null,
            "JSON null is not the CLF dash"
        );
        let ev = parse_json(r#"{"method":"GET","status":"200.0","bytes":18446744073709551615}"#);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Null, "beyond i64");
        let ev = parse_json(r#"{"method":"GET","status":true,"bytes":" 42 "}"#);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Null);
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(42));
        let ev = parse_json(r#"{"method":"GET","status":200}"#);
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Null, "missing");
        let ev = parse_json(r#"{"method":"GET","status":200,"bytes":""}"#);
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(0));
        let ev = parse_json(r#"{"method":"GET","status":404.5,"bytes":1.5}"#);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Null);
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Null);
        let ev = parse_json(r#"{"method":"GET","status":200,"remote_addr":12345,"user":true}"#);
        assert_eq!(
            field(&ev, "c-ip"),
            &s("12345"),
            "non-string values of string taxonomy keys are rendered"
        );
        assert_eq!(field(&ev, "cs-username"), &s("true"));
        for line in [
            r#"{"method":"GET","status":"abc"}"#,
            r#"{"method":"GET","status":"404"}"#,
            r#"{"method":"GET","status":404}"#,
            r#"{"method":"GET","status":null}"#,
            r#"{"method":"GET","status":[404]}"#,
            r#"{"method":"GET","status":{"code":404}}"#,
        ] {
            let ev = parse_json(line);
            assert!(
                matches!(
                    field(&ev, "sc-status"),
                    FieldValue::Int(_) | FieldValue::Null
                ),
                "{line}: {:?}",
                field(&ev, "sc-status")
            );
        }
    }

    #[test]
    fn json_duplicate_keys_last_value_wins_consistently() {
        let ev = parse_json(r#"{"method":"GET","status":200,"method":"POST"}"#);
        assert_eq!(field(&ev, "cs-method"), &s("POST"));
        assert_eq!(field(&ev, "method"), &s("POST"));
        assert_eq!(ev.fields.iter().filter(|(k, _)| k == "method").count(), 1);
        assert_eq!(keys(&ev.fields[7..])[6..], ["method", "status"]);
    }

    #[test]
    fn both_parsers_emit_the_taxonomy_keys_first_and_rule_logsources_match() {
        let text = parse_text(&fixture(APACHE_FIXTURE)[0]);
        let json = parse_json(&fixture(NGINX_FIXTURE)[0]);
        for ev in [&text, &json] {
            assert_eq!(keys(&ev.fields[..7]), DETAILS_KEYS);
            assert_eq!(keys(&ev.fields[7..13]), EXTRA_KEYS);
        }
        assert!(LogSourceSpec::new(None, Some("webserver"), None).matches_any(&text.tags));
        assert!(
            LogSourceSpec::new(Some("apache"), Some("webserver"), None).matches_any(&text.tags)
        );
        assert!(LogSourceSpec::new(Some("apache"), None, Some("access")).matches_any(&text.tags));
        assert!(
            !LogSourceSpec::new(Some("nginx"), Some("webserver"), None).matches_any(&text.tags)
        );
        assert!(LogSourceSpec::new(None, Some("webserver"), None).matches_any(&json.tags));
        assert!(LogSourceSpec::new(Some("nginx"), None, Some("access")).matches_any(&json.tags));
        assert!(!LogSourceSpec::new(Some("apache"), None, Some("access")).matches_any(&json.tags));
        assert!(!LogSourceSpec::new(None, None, Some("apache")).matches_any(&text.tags));
    }

    #[test]
    fn nginx_hex_escapes_are_decoded() {
        assert_eq!(
            unescape_quoted(r"GET /x\x22y HTTP/1.1"),
            "GET /x\"y HTTP/1.1"
        );
        assert_eq!(unescape_quoted(r"a\x5Cb"), "a\\b");
        assert_eq!(unescape_quoted(r"keep \x41 as is"), r"keep \x41 as is");
    }
}
