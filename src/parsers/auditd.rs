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

//! Linux audit records: `/var/log/audit/audit.log` (raw and ENRICHED `log_format`), `ausearch -i`
//! output, and records that `audisp-syslog` forwards to syslog.
//!
//! Every record (line) is one event, as the Sigma `service: auditd` rules expect: `type=EXECVE`
//! rules look at `a0`, `a1`, ...; `type=SYSCALL` rules at `SYSCALL`, `exe`, `comm`, `key`;
//! `type=PATH` rules at `name` and `nametype`.
//!
//! - Raw records quote plain strings (`comm="cat"`) and hex-encode strings auditd considers
//!   untrusted (spaces, quotes, control characters): `proctitle=636174002F6574632F736861646F77`.
//!   Unquoted values of those fields are decoded, the way `ausearch -i` shows them (the NUL
//!   separators of `proctitle` become spaces). Long `EXECVE` arguments split into `a1[0]`, `a1[1]`,
//!   ... are joined back into `a1`.
//! - ENRICHED records append the interpreted fields after a `0x1D` byte with upper-case names
//!   (`SYSCALL=execve UID="root"`); they are added as fields of their own. Raw records get a
//!   `SYSCALL` name from the `arch` and `syscall` number (x86_64 and aarch64) so that rules written
//!   against `SYSCALL` work on them too.
//! - `ausearch -i` prints `msg=audit(04/16/2025 08:20:23.552:47372) :` in the local time of the
//!   machine it ran on (no zone, so `-z` applies) and values unquoted and already decoded:
//!   `EXECVE` arguments are split on the next `aN=` and `proctitle` is the rest of the line.
//! - `msg='op=PAM:session_open acct="root" ... res=success'` payloads of user-space records are
//!   flattened into fields.
//!
//! Unquoted decimal values become numbers (`uid=0`, `exit=0`) so that rules comparing numbers
//! match; everything else stays text.

use super::{LineParser, ParseContext, continuation_event, syscalls, timestamp};
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, Utc};

/// When the record was written.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuditTime {
    /// Raw records: epoch seconds (UTC).
    Epoch(DateTime<Utc>),
    /// `ausearch -i`: local time of the machine that ran `ausearch`, without a zone.
    Local(NaiveDateTime),
}

/// One parsed audit record.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    /// `node=` (the host name when the dispatcher adds it).
    pub node: Option<String>,
    pub record_type: String,
    pub time: Option<AuditTime>,
    pub serial: Option<i64>,
    /// `type`, then the record's fields in order (decoded), then the enriched fields.
    pub fields: Vec<(String, FieldValue)>,
    /// `key="decoded value"` for every hex-encoded value, so that keywords see the text.
    pub decoded: Vec<String>,
}

/// Strip an optional `node=<host> ` prefix: `(node, rest)`.
fn split_node(line: &str) -> (Option<&str>, &str) {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix("node=")
        && let Some((node, after)) = rest.split_once(' ')
    {
        return (Some(node), after.trim_start());
    }
    (None, t)
}

/// `type=SYSCALL msg=audit(` at the start of the line (after an optional `node=`).
pub fn matches_entry(line: &str) -> bool {
    header(line).is_some()
}

/// `(node, type, msg contents, body after the header)`.
fn header(line: &str) -> Option<(Option<&str>, &str, &str, &str)> {
    let (node, rest) = split_node(line);
    let rest = rest.strip_prefix("type=")?;
    let (rtype, rest) = rest.split_once(' ')?;
    if rtype.is_empty()
        || !rtype
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let rest = rest.trim_start().strip_prefix("msg=audit(")?;
    let (msg, body) = rest.split_once(')')?;
    // raw: `): `; ausearch -i: `) : `
    let body = body.trim_start();
    let body = body.strip_prefix(':').unwrap_or(body);
    Some((node, rtype, msg, body))
}

/// `1723042099.699:13369` or `04/16/2025 08:20:23.552:47372` → (time, serial, interpreted).
fn parse_msg(msg: &str) -> (Option<AuditTime>, Option<i64>, bool) {
    let (time, serial) = match msg.rsplit_once(':') {
        Some((t, s)) => (t, s.trim().parse::<i64>().ok()),
        None => (msg, None),
    };
    let time = time.trim();
    if let Ok(secs) = time.parse::<f64>() {
        return (
            timestamp::parse_epoch(secs).map(AuditTime::Epoch),
            serial,
            false,
        );
    }
    (
        parse_interpreted_time(time).map(AuditTime::Local),
        serial,
        true,
    )
}

/// `MM/DD/YYYY HH:MM:SS.mmm` (also `MM/DD/YY`, and `DD/MM/...` when the first number cannot be a
/// month), the `%x %T` that `ausearch -i` prints in the usual locales.
fn parse_interpreted_time(s: &str) -> Option<NaiveDateTime> {
    let (date, clock) = s.split_once(' ')?;
    let mut parts = date.split('/');
    let a: u32 = parts.next()?.parse().ok()?;
    let b: u32 = parts.next()?.parse().ok()?;
    let year_text = parts.next()?;
    let mut year: i32 = year_text.parse().ok()?;
    if year_text.len() == 2 {
        year += 2000;
    }
    let (month, day) = if a > 12 { (b, a) } else { (a, b) };
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let mut hms = hms.split(':');
    let h: u32 = hms.next()?.parse().ok()?;
    let m: u32 = hms.next()?.parse().ok()?;
    let sec: u32 = hms.next()?.parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day)?.and_hms_nano_opt(
        h,
        m,
        sec,
        timestamp::frac_to_nanos(frac),
    )
}

/// One `key=value` of a record body.
#[derive(Clone, Debug, PartialEq)]
struct Token<'a> {
    key: &'a str,
    value: &'a str,
    /// The quote character when the value was quoted.
    quote: Option<char>,
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']')
}

/// Split a record body into `key=value` tokens. Values may be `"double"` or `'single'` quoted
/// (with spaces); anything that is not `key=value` is skipped.
fn tokens(body: &str) -> Vec<Token<'_>> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_key_byte(bytes[i]) {
            i += 1;
        }
        if i == start || i >= bytes.len() || bytes[i] != b'=' {
            // not a key=value: skip the word
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let key = &body[start..i];
        i += 1; // '='
        let (value, quote) = match bytes.get(i) {
            Some(&q @ (b'"' | b'\'')) => {
                let from = i + 1;
                let end = body[from..]
                    .find(q as char)
                    .map_or(body.len(), |p| from + p);
                i = (end + 1).min(body.len());
                (&body[from..end], Some(q as char))
            }
            _ => {
                let from = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                (&body[from..i], None)
            }
        };
        out.push(Token { key, value, quote });
    }
    out
}

/// Fields auditd hex-encodes when their value is an untrusted string.
fn is_encodable(record_type: &str, key: &str) -> bool {
    matches!(
        key,
        "proctitle" | "name" | "cwd" | "comm" | "exe" | "path" | "data" | "cmd" | "key" | "acct"
    ) || (record_type == "EXECVE" && execve_arg(key).is_some())
}

/// `a3` → `(3, None)`, `a3[1]` → `(3, Some(1))`; `None` for other keys.
fn execve_arg(key: &str) -> Option<(usize, Option<usize>)> {
    let rest = key.strip_prefix('a')?;
    let (index, part) = match rest.split_once('[') {
        Some((i, p)) => (i, Some(p.strip_suffix(']')?.parse::<usize>().ok()?)),
        None => (rest, None),
    };
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((index.parse().ok()?, part))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The value of an encodable field: hex-decoded when it was written unquoted.
fn decoded(key: &str, value: &str) -> String {
    match decode_hex(value) {
        Some(bytes) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            match key {
                // the command line's arguments are NUL-separated
                "proctitle" => text.trim_end_matches('\0').replace('\0', " "),
                // several keys are separated by 0x01
                "key" => text.replace('\u{1}', ","),
                _ => text,
            }
        }
        None => value.to_string(),
    }
}

/// An unquoted decimal that survives a round trip becomes a number, anything else text.
fn typed(value: &str) -> FieldValue {
    match value.parse::<i64>() {
        Ok(n) if n.to_string() == value => FieldValue::Int(n),
        _ => FieldValue::Str(value.to_string()),
    }
}

/// Collects the fields of a record: keeps order, replaces repeated keys, joins split arguments.
#[derive(Default)]
struct Fields {
    list: Vec<(String, FieldValue)>,
    /// `aN[i]` pieces: (N, i, text)
    pieces: Vec<(usize, usize, String)>,
    /// `key="decoded"` of the values that were hex-encoded
    decoded: Vec<String>,
}

impl Fields {
    fn push(&mut self, key: &str, value: FieldValue) {
        if let Some(existing) = self.list.iter_mut().find(|(k, _)| k == key) {
            existing.1 = value;
        } else {
            self.list.push((key.to_string(), value));
        }
    }

    fn has(&self, key: &str) -> bool {
        self.list.iter().any(|(k, _)| k == key)
    }

    fn get_str(&self, key: &str) -> Option<String> {
        self.list
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.render())
    }

    /// The value of an encodable field written unquoted: decoded, and remembered for keywords.
    fn decode(&mut self, key: &str, value: &str) -> String {
        let text = decoded(key, value);
        if text != value {
            self.decoded.push(format!("{key}=\"{text}\""));
        }
        text
    }

    fn finish(mut self) -> (Vec<(String, FieldValue)>, Vec<String>) {
        let mut groups = std::collections::BTreeMap::<usize, Vec<(usize, String)>>::new();
        for (n, index, text) in self.pieces.drain(..) {
            groups.entry(n).or_default().push((index, text));
        }
        for (n, mut parts) in groups {
            parts.sort_by_key(|(index, _)| *index);
            let text = parts
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<String>();
            let contiguous = parts
                .iter()
                .enumerate()
                .all(|(expected, (actual, _))| expected == *actual);
            let length_matches = self
                .get_str(&format!("a{n}_len"))
                .and_then(|s| s.parse::<usize>().ok())
                .is_none_or(|expected| expected == text.len());
            if contiguous && length_matches {
                self.push(&format!("a{n}"), FieldValue::Str(text));
            } else {
                for (index, text) in parts {
                    self.push(&format!("a{n}[{index}]"), FieldValue::Str(text));
                }
            }
        }
        (self.list, self.decoded)
    }
}

/// Add the tokens of a raw record body.
fn add_raw_tokens(fields: &mut Fields, record_type: &str, body: &str) {
    for t in tokens(body) {
        if t.key == "msg" && t.quote == Some('\'') {
            // user-space records: msg='op=... acct="root" exe="/usr/bin/sudo" res=success'
            for sub in tokens(t.value) {
                let value = match sub.quote {
                    Some(_) => FieldValue::Str(sub.value.to_string()),
                    None if is_encodable(record_type, sub.key) => {
                        FieldValue::Str(fields.decode(sub.key, sub.value))
                    }
                    None => typed(sub.value),
                };
                fields.push(sub.key, value);
            }
            continue;
        }
        if record_type == "EXECVE"
            && let Some((n, Some(part))) = execve_arg(t.key)
        {
            let text = match t.quote {
                Some(_) => t.value.to_string(),
                None => fields.decode(t.key, t.value),
            };
            fields.pieces.push((n, part, text));
            continue;
        }
        let value = match t.quote {
            Some(_) => FieldValue::Str(t.value.to_string()),
            None if is_encodable(record_type, t.key) => {
                FieldValue::Str(fields.decode(t.key, t.value))
            }
            None => typed(t.value),
        };
        fields.push(t.key, value);
    }
}

/// Add the tokens of an `ausearch -i` record body (values unquoted and already decoded).
fn add_interpreted_tokens(fields: &mut Fields, record_type: &str, body: &str) {
    let body = body.trim_end();
    if record_type == "PROCTITLE"
        && let Some(at) = find_key(body, "proctitle", 0)
    {
        fields.push("proctitle", FieldValue::Str(body[at..].to_string()));
        return;
    }
    if record_type == "EXECVE"
        && let Some(argc_at) = find_key(body, "argc", 0)
    {
        let argc_text: &str = body[argc_at..].split_whitespace().next().unwrap_or("");
        fields.push("argc", typed(argc_text));
        if let Ok(argc) = argc_text.parse::<usize>() {
            let mut from = argc_at;
            for n in 0..argc {
                let Some(start) = find_key(body, &format!("a{n}"), from) else {
                    break;
                };
                let end = if n + 1 < argc {
                    find_key(body, &format!("a{}", n + 1), start)
                        .map_or(body.len(), |next| next - format!("a{}=", n + 1).len())
                } else {
                    body.len()
                };
                let value = body[start..end.max(start)].trim_end();
                fields.push(&format!("a{n}"), FieldValue::Str(value.to_string()));
                from = end.max(start);
            }
            return;
        }
    }
    for t in tokens(body) {
        if t.key == "msg" && t.quote == Some('\'') {
            for sub in tokens(t.value) {
                fields.push(sub.key, interpreted_value(&sub));
            }
            continue;
        }
        fields.push(t.key, interpreted_value(&t));
    }
}

fn interpreted_value(t: &Token<'_>) -> FieldValue {
    match t.quote {
        Some(_) => FieldValue::Str(t.value.to_string()),
        None => typed(t.value),
    }
}

/// The byte offset of the value of ` key=` (at the start or after whitespace), searching from
/// `from`.
fn find_key(body: &str, key: &str, from: usize) -> Option<usize> {
    let needle = format!("{key}=");
    let mut search = from;
    while let Some(p) = body[search..].find(&needle) {
        let at = search + p;
        if at == 0 || body.as_bytes()[at - 1].is_ascii_whitespace() {
            return Some(at + needle.len());
        }
        search = at + needle.len();
    }
    None
}

/// Parse one audit record (a line, or the message of a syslog line). `None` when the text does not
/// start with an audit record header.
pub fn parse_record(text: &str) -> Option<Record> {
    let (node, record_type, msg, body) = header(text)?;
    let (time, serial, interpreted) = parse_msg(msg);
    let mut fields = Fields::default();
    fields.push("type", FieldValue::Str(record_type.to_string()));
    if interpreted {
        add_interpreted_tokens(&mut fields, record_type, body);
    } else {
        let (raw, enriched) = match body.split_once('\u{1d}') {
            Some((r, e)) => (r, Some(e)),
            None => (body, None),
        };
        add_raw_tokens(&mut fields, record_type, raw);
        if let Some(enriched) = enriched {
            for t in tokens(enriched) {
                // the interpreted `SADDR={ fam=inet laddr=... }` group is not a field
                if t.value == "{" {
                    continue;
                }
                fields.push(t.key, FieldValue::Str(t.value.to_string()));
            }
        }
    }
    // `SYSCALL` (the name), which ENRICHED records carry and the rules use
    if !fields.has("SYSCALL")
        && let Some(syscall) = fields.get_str("syscall")
    {
        let name = match syscall.parse::<u16>() {
            Ok(number) => fields
                .get_str("arch")
                .and_then(|arch| syscalls::name(&arch, number))
                .map(str::to_string),
            Err(_) if !syscall.is_empty() => Some(syscall),
            Err(_) => None,
        };
        if let Some(name) = name {
            fields.push("SYSCALL", FieldValue::Str(name));
        }
    }
    let (mut fields, mut decoded) = fields.finish();
    // Header identity remains authoritative even when a user-space msg payload
    // contains a field named type.
    fields.retain(|(key, _)| key != "type");
    fields.insert(
        0,
        ("type".to_owned(), FieldValue::Str(record_type.to_owned())),
    );
    if record_type == "EXECVE"
        && let Some(command) = complete_command_line(&fields)
    {
        fields.retain(|(key, _)| key != "CommandLine");
        fields.push(("CommandLine".to_owned(), FieldValue::Str(command.clone())));
        decoded.push(format!("CommandLine=\"{command}\""));
    }
    if let Some(serial) = serial {
        fields.push(("serial".to_string(), FieldValue::Int(serial)));
    }
    Some(Record {
        node: node.map(str::to_string),
        record_type: record_type.to_string(),
        time,
        serial,
        fields,
        decoded,
    })
}

/// Join only a complete argv vector. Missing indexes must not fabricate adjacency
/// between separated arguments, and argc never determines an allocation size.
fn complete_command_line(fields: &[(String, FieldValue)]) -> Option<String> {
    let argc = fields
        .iter()
        .find(|(key, _)| key == "argc")
        .and_then(|(_, v)| match v {
            FieldValue::Int(n) => usize::try_from(*n).ok(),
            _ => None,
        })?;
    let mut args: Vec<_> = fields
        .iter()
        .filter_map(|(key, value)| {
            let (index, part) = execve_arg(key)?;
            (part.is_none() && key == &format!("a{index}")).then_some((index, value.render()))
        })
        .collect();
    if argc == 0 || args.len() != argc {
        return None;
    }
    args.sort_by_key(|(index, _)| *index);
    if args
        .iter()
        .enumerate()
        .any(|(expected, (actual, _))| expected != *actual)
    {
        return None;
    }
    Some(
        args.into_iter()
            .map(|(_, text)| text)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Build the event of an audit record. `fallback` and `fallback_host` are the time and host of the
/// syslog line that carried the record, used when the record has none of its own.
pub fn record_event(
    raw: &str,
    record: Record,
    ctx: &ParseContext,
    fallback: Option<(DateTime<FixedOffset>, bool)>,
    fallback_host: Option<String>,
    resolve_local: &mut dyn FnMut(NaiveDateTime) -> DateTime<FixedOffset>,
) -> ParsedEvent {
    let mut ev = ParsedEvent::new(raw, &LogSourceTag::LINUX_AUDITD);
    match record.time {
        Some(AuditTime::Epoch(t)) => {
            ev.timestamp = Some(t.fixed_offset());
            ev.tz_explicit = true;
        }
        Some(AuditTime::Local(naive)) => {
            ev.timestamp = Some(resolve_local(naive));
            ev.tz_explicit = false;
        }
        None => {
            if let Some((t, explicit)) = fallback {
                ev.timestamp = Some(t);
                ev.tz_explicit = explicit;
            }
        }
    }
    ev.hostname = record.node.clone().or(fallback_host);
    if !record.decoded.is_empty() {
        ev.match_text = Some(format!("{} {}", raw.trim_end(), record.decoded.join(" ")));
    }
    for (k, v) in record.fields {
        ev.push(&k, v);
    }
    ctx.finish(&mut ev);
    ev
}

/// Parser for audit log files.
pub struct AuditdParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
    warned_resolution: bool,
}

impl AuditdParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self {
            ctx,
            last_ts: None,
            warned_resolution: false,
        }
    }
}

/// Resolve an `ausearch -i` local time in the assumed zone, warning once per file about DST.
pub fn resolve_local(
    naive: NaiveDateTime,
    ctx: &ParseContext,
    warned: &mut bool,
) -> DateTime<FixedOffset> {
    let (dt, res) = timestamp::resolve_naive(naive, &ctx.tz);
    if res != timestamp::Resolution::Exact && !*warned {
        *warned = true;
        crate::errorlog::log_warn(&format!(
            "{}: the local time {naive} is ambiguous or does not exist (DST) in timezone {}. Use -z to set the zone of the log.",
            ctx.display_name, ctx.tz
        ));
    }
    dt
}

impl LineParser for AuditdParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        let trimmed = line.trim();
        // blank lines and the `----` / `time->` separators of ausearch output
        if trimmed.is_empty() || trimmed.bytes().all(|b| b == b'-') || trimmed.starts_with("time->")
        {
            return None;
        }
        match parse_record(line) {
            Some(record) => {
                let ctx = &self.ctx;
                let warned = &mut self.warned_resolution;
                let mut resolve = |naive| resolve_local(naive, ctx, warned);
                let ev = record_event(line, record, ctx, None, None, &mut resolve);
                if ev.timestamp.is_some() {
                    self.last_ts = ev.timestamp;
                }
                Some(ev)
            }
            None => {
                let mut ev =
                    continuation_event(line, &LogSourceTag::LINUX_AUDITD, &[], self.last_ts);
                self.ctx.finish(&mut ev);
                Some(ev)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fields(text: &str) -> Vec<(String, FieldValue)> {
        parse_record(text).unwrap().fields
    }

    fn get<'a>(f: &'a [(String, FieldValue)], key: &str) -> Option<&'a FieldValue> {
        f.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn s(v: &str) -> FieldValue {
        FieldValue::Str(v.to_string())
    }

    #[test]
    fn reconstructed_argv_is_ordered_and_never_fills_missing_fragments() {
        let f = fields(r#"type=EXECVE msg=audit(1:2): argc=3 a2="last" a0="command" a1="first""#);
        assert_eq!(get(&f, "CommandLine"), Some(&s("command first last")));
        for line in [
            r#"type=EXECVE msg=audit(1:2): argc=3 a0="command" a2="last""#,
            r#"type=EXECVE msg=audit(1:2): argc=3 a0="sysctl" a1="-w" a2[0]="kernel.randomize" a2[2]="_va_space=0""#,
            r#"type=EXECVE msg=audit(1:2): argc=3 a0="sysctl" a1="-w" a2_len=100 a2[0]="kernel.randomize" a2[1]="_va_space=0""#,
            r#"type=EXECVE msg=audit(1:2): argc=9223372036854775807 a0="command""#,
        ] {
            let f = fields(line);
            assert!(get(&f, "CommandLine").is_none(), "{f:?}");
        }
    }
    #[test]
    fn user_message_fields_cannot_replace_the_audit_record_type() {
        let f = fields("type=USER msg=audit(1:2): msg='type=EXECVE argc=2 a0=init a1=0'");
        assert_eq!(get(&f, "type"), Some(&s("USER")));
        assert!(get(&f, "CommandLine").is_none());
    }

    #[test]
    fn entries_need_a_type_and_an_audit_header() {
        assert!(matches_entry(
            "type=SYSCALL msg=audit(1723042099.699:13369): arch=c000003e syscall=59"
        ));
        assert!(matches_entry(
            "node=web01 type=EXECVE msg=audit(1723042099.699:13369): argc=1 a0=\"ls\""
        ));
        assert!(matches_entry(
            "type=PROCTITLE msg=audit(04/16/2025 08:20:23.552:47372) : proctitle=whoami"
        ));
        assert!(!matches_entry("type=syscall msg=audit(1:2): x=1"));
        assert!(!matches_entry("Oct 26 17:39:01 host sshd[1]: type=SYSCALL"));
        assert!(!matches_entry("type=SYSCALL arch=c000003e"));
    }

    #[test]
    fn raw_syscall_records_get_numbers_text_and_the_syscall_name() {
        let f = fields(
            r#"type=SYSCALL msg=audit(1723214214.268:131846): arch=c000003e syscall=59 success=yes exit=0 a0=55acfa8e7308 items=2 ppid=75428 pid=75479 auid=1000 uid=0 tty=pts0 comm="whoami" exe="/usr/bin/whoami" subj=unconfined key="recon""#,
        );
        assert_eq!(get(&f, "type"), Some(&s("SYSCALL")));
        assert_eq!(get(&f, "syscall"), Some(&FieldValue::Int(59)));
        assert_eq!(get(&f, "SYSCALL"), Some(&s("execve")));
        assert_eq!(get(&f, "uid"), Some(&FieldValue::Int(0)));
        assert_eq!(get(&f, "a0"), Some(&s("55acfa8e7308")));
        assert_eq!(get(&f, "comm"), Some(&s("whoami")));
        assert_eq!(get(&f, "key"), Some(&s("recon")));
        assert_eq!(get(&f, "serial"), Some(&FieldValue::Int(131846)));
        let r = parse_record("type=SYSCALL msg=audit(1723214214.268:1): arch=c000003e syscall=59")
            .unwrap();
        assert_eq!(
            r.time,
            Some(AuditTime::Epoch(
                DateTime::parse_from_rfc3339("2024-08-09T14:36:54.268Z")
                    .unwrap()
                    .to_utc()
            ))
        );
    }

    #[test]
    fn hex_encoded_values_are_decoded() {
        let f = fields(
            "type=PROCTITLE msg=audit(1723042099.699:13369): proctitle=7375646F00636174002F6574632F736861646F77",
        );
        assert_eq!(get(&f, "proctitle"), Some(&s("sudo cat /etc/shadow")));
        let f =
            fields(r#"type=EXECVE msg=audit(1:2): argc=3 a0="sh" a1="-c" a2=6563686F2068656C6C6F"#);
        assert_eq!(get(&f, "a0"), Some(&s("sh")));
        assert_eq!(get(&f, "a2"), Some(&s("echo hello")));
        assert_eq!(get(&f, "argc"), Some(&FieldValue::Int(3)));
        // a quoted value is never decoded, and syscall arguments of SYSCALL records are numbers
        let f = fields(r#"type=PATH msg=audit(1:2): item=0 name="CAFE" nametype=NORMAL"#);
        assert_eq!(get(&f, "name"), Some(&s("CAFE")));
        let f = fields("type=PATH msg=audit(1:2): item=0 name=2F746D702F612062 nametype=CREATE");
        assert_eq!(get(&f, "name"), Some(&s("/tmp/a b")));
        let f = fields("type=SYSCALL msg=audit(1:2): arch=c000003e syscall=1 key=(null)");
        assert_eq!(get(&f, "key"), Some(&s("(null)")));
    }

    #[test]
    fn split_execve_arguments_are_joined() {
        let f = fields(
            r#"type=EXECVE msg=audit(1:2): argc=2 a0="echo" a1_len=10 a1[0]=68656C6C6F a1[1]="world""#,
        );
        assert_eq!(get(&f, "a1"), Some(&s("helloworld")));
        assert_eq!(get(&f, "a1_len"), Some(&FieldValue::Int(10)));
        assert!(get(&f, "a1[0]").is_none());
    }

    #[test]
    fn enriched_fields_and_user_messages_are_flattened() {
        let f = fields(
            "type=SYSCALL msg=audit(1724076881.293:4522): arch=c000003e syscall=42 success=yes uid=1000 comm=\"route\" key=\"network_connect_4\"\u{1d}ARCH=x86_64 SYSCALL=connect AUID=\"ubuntu\" UID=\"ubuntu\"",
        );
        assert_eq!(get(&f, "SYSCALL"), Some(&s("connect")));
        assert_eq!(get(&f, "UID"), Some(&s("ubuntu")));
        assert_eq!(get(&f, "uid"), Some(&FieldValue::Int(1000)));
        let f = fields(
            "type=SERVICE_STOP msg=audit(1722965459.146:15207): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=sysmon comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'\u{1d}UID=\"root\" AUID=\"unset\"",
        );
        assert_eq!(get(&f, "unit"), Some(&s("sysmon")));
        assert_eq!(get(&f, "exe"), Some(&s("/usr/lib/systemd/systemd")));
        assert_eq!(get(&f, "res"), Some(&s("success")));
        assert_eq!(get(&f, "AUID"), Some(&s("unset")));
        assert!(get(&f, "msg").is_none());
    }

    #[test]
    fn ausearch_interpreted_records() {
        let r = parse_record(
            "type=SYSCALL msg=audit(04/16/2025 08:20:23.552:47372) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5f43d73edef0 auid=ubuntu uid=ubuntu comm=whoami exe=/usr/bin/whoami subj=unconfined key=recon ",
        )
        .unwrap();
        assert_eq!(
            r.time,
            Some(AuditTime::Local(
                NaiveDate::from_ymd_opt(2025, 4, 16)
                    .unwrap()
                    .and_hms_milli_opt(8, 20, 23, 552)
                    .unwrap()
            ))
        );
        assert_eq!(r.serial, Some(47372));
        assert_eq!(get(&r.fields, "SYSCALL"), Some(&s("execve")));
        assert_eq!(get(&r.fields, "exe"), Some(&s("/usr/bin/whoami")));
        let f = fields(
            "type=EXECVE msg=audit(06/05/2025 09:37:05.888:7488) : argc=3 a0=sh a1=-c a2=systemctl daemon-reload ",
        );
        assert_eq!(get(&f, "a0"), Some(&s("sh")));
        assert_eq!(get(&f, "a1"), Some(&s("-c")));
        assert_eq!(get(&f, "a2"), Some(&s("systemctl daemon-reload")));
        let f = fields(
            "type=PROCTITLE msg=audit(02/20/2025 13:07:46.504:118908) : proctitle=cat /etc/shadow /etc/gshadow ",
        );
        assert_eq!(
            get(&f, "proctitle"),
            Some(&s("cat /etc/shadow /etc/gshadow"))
        );
        // a day that cannot be a month means DD/MM
        assert_eq!(
            parse_interpreted_time("16/04/25 08:20:23.5"),
            NaiveDate::from_ymd_opt(2025, 4, 16)
                .unwrap()
                .and_hms_milli_opt(8, 20, 23, 500)
        );
    }

    #[test]
    fn keywords_see_decoded_values() {
        crate::errorlog::set_quiet(true);
        let ctx = ParseContext::new(Path::new("audit.log"), Default::default());
        let mut p = AuditdParser::new(ctx);
        // grep -ri "my password" /etc: the argument with a space is hex-encoded
        let ev = p
            .parse_line(
                r#"type=EXECVE msg=audit(1723042099.699:7): argc=4 a0="grep" a1="-ri" a2=6D792070617373776F7264 a3="/etc""#,
            )
            .unwrap();
        assert_eq!(ev.field_str("a2"), Some("my password"));
        assert!(
            !ev.raw.contains("my password"),
            "the line is shown as written"
        );
        let rule = sigma_rust::rule_from_yaml(
            "title: t\nlogsource: {product: linux, service: auditd}\ndetection:\n  sel:\n    type: EXECVE\n  kw:\n    'raw|contains|all':\n      - grep\n      - password\n  condition: sel and kw\n",
        )
        .unwrap();
        assert!(rule.is_match(&ev.to_sigma_event()));
    }

    #[test]
    fn node_prefix_is_the_host() {
        let r = parse_record("node=web01 type=CWD msg=audit(1:2): cwd=\"/root\"").unwrap();
        assert_eq!(r.node.as_deref(), Some("web01"));
        assert_eq!(get(&r.fields, "cwd"), Some(&s("/root")));
    }

    #[test]
    fn parser_builds_auditd_events() {
        crate::errorlog::set_quiet(true);
        let ctx = ParseContext::new(Path::new("/var/log/audit/audit.log"), Default::default());
        let mut p = AuditdParser::new(ctx);
        let ev = p
            .parse_line(
                "node=web01 type=EXECVE msg=audit(1723042099.699:13369): argc=2 a0=\"cat\" a1=\"/etc/shadow\"",
            )
            .unwrap();
        assert_eq!(ev.primary_logsource, "linux/auditd");
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        assert!(ev.tz_explicit);
        assert_eq!(ev.field_str("a1"), Some("/etc/shadow"));
        assert!(p.parse_line("----").is_none());
        assert!(p.parse_line("").is_none());
        let cont = p.parse_line("garbage").unwrap();
        assert!(cont.timestamp_inferred);
        let rule = sigma_rust::rule_from_yaml(
            "title: t\nlogsource: {product: linux, service: auditd}\ndetection:\n  sel:\n    type: EXECVE\n    a0: cat\n    a1|contains: shadow\n  condition: sel\n",
        )
        .unwrap();
        assert!(rule.is_match(&ev.to_sigma_event()));
    }
}
