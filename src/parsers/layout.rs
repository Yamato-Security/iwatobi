//! Field layouts: custom log formats from `config/custom_log_formats.yaml` (an nginx
//! `log_format`, an Apache `LogFormat` or a regex with named groups) and access log layouts that
//! are detected automatically (amendment A21).
//!
//! Every layout compiles to one anchored regex whose capture groups are named fields. A web
//! server layout hands those fields to the same mapping as the JSON access logs, so
//! `$remote_addr`, `%h` and a `(?P<remote_addr>…)` group all become `c-ip`. An automatically
//! detected layout is written as an nginx `log_format` string and compiled from it, so the layout
//! iwatobi prints is exactly what a user pastes into the configuration file to pin or correct it.

use super::access::{self, RecordBuilder};
use super::timestamp::{self, Resolution};
use super::{LineParser, ParseContext, continuation_event};
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::{LogSourceTag, SUPPORTED_TAGS};
use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// The custom formats shipped in `config/custom_log_formats.yaml` (only commented examples).
pub const DEFAULT_CUSTOM_FORMATS: &str = include_str!("../../config/custom_log_formats.yaml");

/// Where a layout came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A format the user configured.
    Custom,
    /// An access log layout iwatobi worked out from the file itself.
    Auto,
}

/// What the fields of a layout describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A web server access log: the fields are mapped to the Sigma `webserver` taxonomy.
    /// `product` adds the Apache / nginx tags; `None` takes them from the file path.
    Webserver { product: Option<&'static str> },
    /// Any other log source: the fields keep their names.
    Other { tag: LogSourceTag },
}

/// One capture group of a layout.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Column {
    name: String,
    /// Written between double quotes: `\"` and `\\` escapes are undone.
    quoted: bool,
}

/// A compiled layout.
#[derive(Debug)]
pub struct Layout {
    pub name: String,
    pub origin: Origin,
    pub kind: Kind,
    regex: Regex,
    /// The column of each capture group (group `i` is `columns[i - 1]`); `None` for an unnamed
    /// group of a user regex.
    columns: Vec<Option<Column>>,
    time_format: Option<String>,
    files: Vec<glob::Pattern>,
    /// The layout as written in the configuration, or as an nginx `log_format` string for a
    /// detected layout.
    pub display: String,
}

impl Layout {
    /// The format name shown with `-v` and counted in the summary: `custom:<name>` or
    /// `access-auto`.
    pub fn format_name(&self) -> String {
        match self.origin {
            Origin::Custom => format!("custom:{}", self.name),
            Origin::Auto => "access-auto".to_string(),
        }
    }

    pub fn matches(&self, line: &str) -> bool {
        self.regex.is_match(line)
    }

    /// Whether the layout restricts itself to some files with `files:`.
    pub fn has_file_filter(&self) -> bool {
        !self.files.is_empty()
    }

    /// Whether the layout may be used for `path`: always without `files:`, otherwise when a
    /// pattern matches the file name (or, for a pattern with a `/`, the whole path).
    pub fn applies_to(&self, path: &Path) -> bool {
        if self.files.is_empty() {
            return true;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let full = path.to_string_lossy().replace('\\', "/");
        self.files.iter().any(|p| {
            if p.as_str().contains('/') {
                p.matches(&full)
            } else {
                p.matches(&name)
            }
        })
    }

    /// The named fields of a line, in layout order, or `None` when the line does not match.
    fn fields(&self, line: &str) -> Option<Vec<(String, FieldValue)>> {
        let caps = self.regex.captures(line.trim_end_matches(['\r', '\n']))?;
        let mut out = Vec::with_capacity(self.columns.len());
        for (i, column) in self.columns.iter().enumerate() {
            let Some(column) = column else {
                continue;
            };
            let text = caps.get(i + 1).map_or("", |m| m.as_str());
            let value = if column.quoted {
                access::unescape_quoted(text).into_owned()
            } else {
                text.to_string()
            };
            out.push((column.name.clone(), FieldValue::Str(value)));
        }
        Some(out)
    }
}

// ------------------------------------------------------------------------------------------------
// Compiling format strings
// ------------------------------------------------------------------------------------------------

/// A layout before it gets a name: the regex source, its columns and a time format.
#[derive(Debug)]
struct Compiled {
    regex: String,
    columns: Vec<Option<Column>>,
    time_format: Option<String>,
}

/// A piece of a format string.
#[derive(Clone, Debug, PartialEq)]
enum Piece {
    Literal(String),
    /// A field and, for an Apache `%{format}t`, the time format it implies.
    Field {
        name: String,
        pattern: FieldPattern,
    },
}

/// How a field's value is matched when the format does not quote or bracket it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum FieldPattern {
    /// One space-free token (possibly empty).
    Token,
    /// `10/Oct/2026:13:55:36 +0900` without brackets.
    ClfTime,
    /// Apache `%t`: the brackets are part of the value.
    BracketedTime,
    /// Free text up to what follows (Apache `%{format}t`, an unquoted `%r`).
    Lazy,
}

/// Quoted field value: anything but an unescaped `"`.
const QUOTED: &str = r#"((?:[^"\\]|\\.)*)"#;

/// Build the regex of a sequence of pieces: a field between `"` literals is a quoted value,
/// between `[` and `]` a bracketed one, otherwise its own pattern. Repeated field names get a
/// `_2`, `_3`, … suffix so that no value is lost.
fn compile_pieces(pieces: &[Piece], time_format: Option<String>) -> Result<Compiled, String> {
    if !pieces.iter().any(|p| matches!(p, Piece::Field { .. })) {
        return Err("the format has no fields".to_string());
    }
    let mut regex = String::from("^");
    let mut columns = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (i, piece) in pieces.iter().enumerate() {
        match piece {
            Piece::Literal(text) => regex.push_str(&regex::escape(text)),
            Piece::Field { name, pattern } => {
                let before = match i.checked_sub(1).map(|j| &pieces[j]) {
                    Some(Piece::Literal(t)) => t.chars().last(),
                    _ => None,
                };
                let after = match pieces.get(i + 1) {
                    Some(Piece::Literal(t)) => t.chars().next(),
                    _ => None,
                };
                let quoted = before == Some('"') && after == Some('"');
                let group = if quoted {
                    QUOTED
                } else if *pattern == FieldPattern::BracketedTime {
                    r"\[([^\]]*)\]"
                } else if before == Some('[') && after == Some(']') {
                    r"([^\]]*)"
                } else {
                    match pattern {
                        FieldPattern::Token => r"(\S*)",
                        FieldPattern::ClfTime => {
                            r"(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})"
                        }
                        FieldPattern::Lazy => r"(.*?)",
                        FieldPattern::BracketedTime => unreachable!("handled above"),
                    }
                };
                regex.push_str(group);
                let n = seen.entry(name.clone()).or_insert(0);
                *n += 1;
                let name = if *n == 1 {
                    name.clone()
                } else {
                    format!("{name}_{n}")
                };
                columns.push(Some(Column { name, quoted }));
            }
        }
    }
    regex.push_str(r"\s*$");
    Ok(Compiled {
        regex,
        columns,
        time_format,
    })
}

/// The format text of an nginx `log_format`: either the format itself or the whole directive
/// (`log_format main '$remote_addr …' '"$http_user_agent"';`), whose quoted parts are joined.
fn nginx_format_text(input: &str) -> String {
    let t = input.trim();
    let Some(rest) = t.strip_prefix("log_format") else {
        return t.to_string();
    };
    let mut out = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' || c == '"' {
            let quote = c;
            while let Some(d) = chars.next() {
                if d == '\\' {
                    if let Some(e) = chars.next() {
                        out.push(e);
                    }
                } else if d == quote {
                    break;
                } else {
                    out.push(d);
                }
            }
        }
    }
    if out.is_empty() { t.to_string() } else { out }
}

/// Compile an nginx `log_format` (amendment A21). `$name` and `${name}` are fields named after
/// the variable; `$time_local` written without brackets keeps its space.
fn compile_nginx(input: &str) -> Result<Compiled, String> {
    let text = nginx_format_text(input);
    let mut pieces: Vec<Piece> = Vec::new();
    let mut literal = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let name = if c == '$' {
            if chars.get(i + 1) == Some(&'{') {
                let end = chars[i + 2..].iter().position(|&c| c == '}');
                end.map(|e| (chars[i + 2..i + 2 + e].iter().collect::<String>(), e + 3))
            } else {
                let len = chars[i + 1..]
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                    .count();
                (len > 0).then(|| {
                    (
                        chars[i + 1..i + 1 + len].iter().collect::<String>(),
                        len + 1,
                    )
                })
            }
        } else {
            None
        };
        match name {
            Some((name, consumed)) if !name.is_empty() => {
                if !literal.is_empty() {
                    pieces.push(Piece::Literal(std::mem::take(&mut literal)));
                }
                let pattern = if name == "time_local" {
                    FieldPattern::ClfTime
                } else {
                    FieldPattern::Token
                };
                pieces.push(Piece::Field { name, pattern });
                i += consumed;
            }
            _ => {
                literal.push(c);
                i += 1;
            }
        }
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    compile_pieces(&pieces, None)
}

/// The format text of an Apache `LogFormat`: the format itself or the whole directive
/// (`LogFormat "%h %l %u %t \"%r\" %>s %b" common`), with `\"` unescaped.
fn apache_format_text(input: &str) -> String {
    let t = input.trim();
    let body = match t
        .strip_prefix("LogFormat")
        .or_else(|| t.strip_prefix("CustomLog"))
    {
        Some(rest) => {
            let rest = rest.trim_start();
            // CustomLog <file> "<format>": skip the file name
            let rest = if t.starts_with("CustomLog") && !rest.starts_with('"') {
                rest.split_once(' ').map_or("", |(_, r)| r.trim_start())
            } else {
                rest
            };
            match rest.strip_prefix('"') {
                Some(inner) => {
                    let mut out = String::new();
                    let mut chars = inner.chars();
                    while let Some(c) = chars.next() {
                        match c {
                            '\\' => {
                                if let Some(d) = chars.next() {
                                    out.push(d);
                                }
                            }
                            '"' => break,
                            _ => out.push(c),
                        }
                    }
                    return out;
                }
                None => rest.to_string(),
            }
        }
        None => t.to_string(),
    };
    body.replace("\\\"", "\"")
}

/// `User-Agent` → `user_agent`.
fn header_name(h: &str) -> String {
    h.trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// The field (and pattern) of one Apache directive, or an error for an unknown one.
fn apache_directive(
    letter: &str,
    param: Option<&str>,
    time_format: &mut Option<String>,
) -> Result<(String, FieldPattern), String> {
    let token = |n: &str| Ok((n.to_string(), FieldPattern::Token));
    match (letter, param) {
        ("h", _) | ("a", None) => token("remote_addr"),
        ("a", Some("c")) => token("peer_ip"),
        ("A", _) => token("server_addr"),
        ("b", _) | ("B", _) => token("body_bytes_sent"),
        ("D", _) => token("request_time_us"),
        ("T", Some("ms")) => token("request_time_ms"),
        ("T", Some("us")) => token("request_time_us"),
        ("T", _) => token("request_time"),
        ("f", _) => token("request_filename"),
        ("H", _) => token("server_protocol"),
        ("k", _) => token("keepalive_requests"),
        ("l", _) => token("ident"),
        ("L", _) => token("log_id"),
        ("m", _) => token("request_method"),
        ("p", Some("remote")) => token("remote_port"),
        ("p", _) => token("server_port"),
        ("P", Some("tid")) | ("P", Some("hextid")) => token("tid"),
        ("P", _) => token("pid"),
        ("q", _) => token("args"),
        ("r", _) => Ok(("request".to_string(), FieldPattern::Lazy)),
        ("R", _) => token("handler"),
        ("s", _) => token("status"),
        ("t", None) => Ok(("time_local".to_string(), FieldPattern::BracketedTime)),
        ("t", Some(p)) => {
            let p = p
                .strip_prefix("begin:")
                .or_else(|| p.strip_prefix("end:"))
                .unwrap_or(p);
            // sec / msec / usec (and their _frac forms) are epoch numbers, which need no format
            if !matches!(p, "sec" | "msec" | "usec" | "msec_frac" | "usec_frac") {
                *time_format = Some(p.to_string());
            }
            Ok(("time".to_string(), FieldPattern::Lazy))
        }
        ("u", _) => token("remote_user"),
        ("U", _) => token("uri"),
        ("v", _) => token("host"),
        ("V", _) => token("server_name"),
        ("X", _) => token("connection_status"),
        ("I", _) => token("bytes_received"),
        ("O", _) => token("bytes_sent"),
        ("S", _) => token("bytes_transferred"),
        ("i", Some(h)) => token(&format!("http_{}", header_name(h))),
        ("o", Some(h)) => token(&format!("sent_http_{}", header_name(h))),
        ("C", Some(h)) => token(&format!("cookie_{}", header_name(h))),
        ("e", Some(h)) => token(&format!("env_{}", header_name(h))),
        ("n", Some(h)) => token(&format!("note_{}", header_name(h))),
        ("^ti", Some(h)) => token(&format!("trailer_in_{}", header_name(h))),
        ("^to", Some(h)) => token(&format!("trailer_out_{}", header_name(h))),
        _ => Err(format!(
            "unsupported Apache directive %{}{letter}",
            param.map(|p| format!("{{{p}}}")).unwrap_or_default()
        )),
    }
}

/// Compile an Apache `LogFormat` (amendment A21). Directives map to the nginx variable names
/// the access log mapping knows (`%h` → `remote_addr`, `%{User-Agent}i` → `http_user_agent`).
fn compile_apache(input: &str) -> Result<Compiled, String> {
    let text = apache_format_text(input);
    let chars: Vec<char> = text.chars().collect();
    let mut pieces: Vec<Piece> = Vec::new();
    let mut literal = String::new();
    let mut time_format = None;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '%' {
            literal.push(chars[i]);
            i += 1;
            continue;
        }
        i += 1;
        if chars.get(i) == Some(&'%') {
            literal.push('%');
            i += 1;
            continue;
        }
        // modifiers: < or > (original / final request), !, status codes
        while i < chars.len() && matches!(chars[i], '<' | '>' | '!' | ',' | '0'..='9') {
            i += 1;
        }
        let mut param = None;
        if chars.get(i) == Some(&'{') {
            let end = chars[i + 1..]
                .iter()
                .position(|&c| c == '}')
                .ok_or("unterminated %{…} in the Apache format")?;
            param = Some(chars[i + 1..i + 1 + end].iter().collect::<String>());
            i += end + 2;
        }
        let letter: String = if chars.get(i) == Some(&'^') {
            let l: String = chars
                .get(i..i + 3)
                .map(|s| s.iter().collect())
                .unwrap_or_default();
            i += 3;
            l
        } else {
            let l = chars
                .get(i)
                .map(|c| c.to_string())
                .ok_or("the Apache format ends with %")?;
            i += 1;
            l
        };
        let (name, pattern) = apache_directive(&letter, param.as_deref(), &mut time_format)?;
        if !literal.is_empty() {
            pieces.push(Piece::Literal(std::mem::take(&mut literal)));
        }
        pieces.push(Piece::Field { name, pattern });
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    compile_pieces(&pieces, time_format)
}

/// Field names of the Sigma `webserver` taxonomy, which regex group names cannot spell (no `-`
/// in a group name): `c_ip` stands for `c-ip`.
const HYPHENATED: &[&str] = &[
    "c-ip",
    "cs-method",
    "cs-uri-query",
    "cs-uri-stem",
    "cs-uri",
    "cs-version",
    "sc-status",
    "sc-bytes",
    "cs-referer",
    "cs-user-agent",
    "cs-host",
    "cs-username",
    "c-useragent",
    "s-port",
    "cs-bytes",
    "time-taken",
];

/// Compile a user regex: every named group is a field.
fn compile_regex(source: &str) -> Result<Compiled, String> {
    let re = Regex::new(source).map_err(|e| format!("invalid regex: {e}"))?;
    let columns: Vec<Option<Column>> = re
        .capture_names()
        .skip(1)
        .map(|name| {
            name.map(|n| {
                let hyphenated = n.replace('_', "-");
                let name = if HYPHENATED.contains(&hyphenated.as_str()) {
                    hyphenated
                } else {
                    n.to_string()
                };
                Column {
                    name,
                    quoted: false,
                }
            })
        })
        .collect();
    if columns.iter().all(Option::is_none) {
        return Err("the regex has no named groups ((?P<name>…))".to_string());
    }
    Ok(Compiled {
        regex: source.to_string(),
        columns,
        time_format: None,
    })
}

// ------------------------------------------------------------------------------------------------
// Configuration file
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    formats: Option<Vec<ConfigEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigEntry {
    name: String,
    nginx: Option<String>,
    apache: Option<String>,
    regex: Option<String>,
    files: Option<Vec<String>>,
    time_format: Option<String>,
    logsource: Option<ConfigLogsource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigLogsource {
    product: Option<String>,
    category: Option<String>,
    service: Option<String>,
}

/// The custom formats of a configuration file, tried in file order.
#[derive(Debug, Default)]
pub struct FormatRegistry {
    pub formats: Vec<Arc<Layout>>,
}

impl FormatRegistry {
    /// Parse `config/custom_log_formats.yaml`. Every problem is an error naming the format.
    pub fn parse(yaml: &str) -> Result<Self, String> {
        let has_content = yaml
            .lines()
            .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'));
        if !has_content {
            return Ok(Self::default());
        }
        let file: ConfigFile = yaml_serde::from_str(yaml).map_err(|e| e.to_string())?;
        let mut formats: Vec<Arc<Layout>> = Vec::new();
        for entry in file.formats.unwrap_or_default() {
            let name = entry.name.trim().to_string();
            let layout = build_entry(entry).map_err(|e| format!("format \"{name}\": {e}"))?;
            if formats.iter().any(|f| f.name == layout.name) {
                return Err(format!("format \"{name}\" is defined twice"));
            }
            formats.push(Arc::new(layout));
        }
        Ok(Self { formats })
    }

    pub fn get(&self, name: &str) -> Option<Arc<Layout>> {
        let name = name.trim().strip_prefix("custom:").unwrap_or(name.trim());
        self.formats.iter().find(|f| f.name == name).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.formats.is_empty()
    }
}

fn build_entry(entry: ConfigEntry) -> Result<Layout, String> {
    let name = entry.name.trim().to_string();
    if name.is_empty() {
        return Err("the name is empty".to_string());
    }
    if super::LogFormat::from_name(&name).is_some() || name == "access-auto" {
        return Err("the name is a built-in format name".to_string());
    }
    let defined = [&entry.nginx, &entry.apache, &entry.regex]
        .iter()
        .filter(|v| v.is_some())
        .count();
    if defined != 1 {
        return Err("give exactly one of nginx, apache or regex".to_string());
    }
    let (compiled, display, product) = if let Some(f) = &entry.nginx {
        (compile_nginx(f)?, f.trim().to_string(), Some("nginx"))
    } else if let Some(f) = &entry.apache {
        (compile_apache(f)?, f.trim().to_string(), Some("apache"))
    } else {
        let f = entry.regex.as_deref().unwrap_or_default();
        (compile_regex(f)?, f.to_string(), None)
    };
    let kind = match &entry.logsource {
        None => Kind::Webserver { product },
        Some(_) if entry.regex.is_none() => {
            return Err("logsource is only used with regex (nginx and apache formats are web server access logs)".to_string());
        }
        Some(ls) => logsource_kind(ls)?,
    };
    let files = entry
        .files
        .unwrap_or_default()
        .iter()
        .map(|p| glob::Pattern::new(p).map_err(|e| format!("files: {p}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let regex = Regex::new(&compiled.regex).map_err(|e| format!("invalid format: {e}"))?;
    Ok(Layout {
        name,
        origin: Origin::Custom,
        kind,
        regex,
        columns: compiled.columns,
        time_format: entry.time_format.or(compiled.time_format),
        files,
        display,
    })
}

/// The kind of a regex format from its `logsource`, which must be one iwatobi's rules use.
fn logsource_kind(ls: &ConfigLogsource) -> Result<Kind, String> {
    let norm = |v: &Option<String>| v.as_ref().map(|s| s.trim().to_ascii_lowercase());
    let (product, category, service) = (norm(&ls.product), norm(&ls.category), norm(&ls.service));
    let tag = SUPPORTED_TAGS
        .iter()
        .find(|t| {
            t.product.map(str::to_string) == product
                && t.category.map(str::to_string) == category
                && t.service.map(str::to_string) == service
        })
        .ok_or_else(|| {
            let names: Vec<String> = SUPPORTED_TAGS
                .iter()
                .map(|t| {
                    let mut parts = Vec::new();
                    if let Some(p) = t.product {
                        parts.push(format!("product: {p}"));
                    }
                    if let Some(c) = t.category {
                        parts.push(format!("category: {c}"));
                    }
                    if let Some(s) = t.service {
                        parts.push(format!("service: {s}"));
                    }
                    format!("{{{}}}", parts.join(", "))
                })
                .collect();
            format!("unsupported logsource; use one of {}", names.join(" "))
        })?;
    Ok(if tag.category == Some("webserver") {
        Kind::Webserver {
            product: tag.product,
        }
    } else {
        Kind::Other { tag: *tag }
    })
}

// ------------------------------------------------------------------------------------------------
// Automatic access log layouts
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TokenKind {
    Bare,
    Quoted,
    Bracketed,
}

/// Split a line into space-separated tokens, keeping `"…"` (with `\` escapes) and `[…]` whole.
/// `None` for an unterminated quote or bracket, or text glued to a closing one.
fn tokenize(line: &str) -> Option<Vec<(TokenKind, &str)>> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' || bytes[i] == b'\t' {
            i += 1;
            continue;
        }
        let (kind, start, end, next) = match bytes[i] {
            b'"' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += if bytes[j] == b'\\' { 2 } else { 1 };
                }
                if j >= bytes.len() {
                    return None;
                }
                (TokenKind::Quoted, i + 1, j, j + 1)
            }
            b'[' => {
                let j = i + line[i..].find(']')?;
                (TokenKind::Bracketed, i + 1, j, j + 1)
            }
            _ => {
                let j = line[i..].find([' ', '\t']).map_or(bytes.len(), |p| i + p);
                (TokenKind::Bare, i, j, j)
            }
        };
        if next < bytes.len() && bytes[next] != b' ' && bytes[next] != b'\t' {
            return None;
        }
        out.push((kind, &line[start..end]));
        i = next;
    }
    Some(out)
}

/// What a column's values look like.
#[derive(Clone, Copy, Debug, Default)]
struct ColumnTraits {
    time_clf: bool,
    time_other: bool,
    epoch: bool,
    iso_time: bool,
    request: bool,
    method: bool,
    protocol: bool,
    status: bool,
    ip: bool,
    integer: bool,
    path: bool,
    url_or_dash: bool,
    user_agent: bool,
    hostname: bool,
}

fn is_dash(v: &str) -> bool {
    v.is_empty() || v == "-"
}

const COMMON_METHODS: &[&str] = &["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"];

fn is_ip_list(v: &str) -> bool {
    v.split(',')
        .all(|p| !p.is_empty() && p.trim().parse::<IpAddr>().is_ok())
}

fn is_hostname(v: &str) -> bool {
    let host = v.rsplit_once(':').map_or(v, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            v
        }
    });
    host.contains('.')
        && host.chars().any(|c| c.is_ascii_alphabetic())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && host.parse::<IpAddr>().is_err()
}

fn is_url(v: &str) -> bool {
    v.starts_with("http://") || v.starts_with("https://")
}

/// The traits that hold for at least 90 % of a column's non-empty values.
fn column_traits(values: &[&str], kind: TokenKind) -> ColumnTraits {
    let present: Vec<&str> = values.iter().copied().filter(|v| !is_dash(v)).collect();
    let mut t = ColumnTraits::default();
    if present.is_empty() {
        t.url_or_dash = true;
        return t;
    }
    let most = |pred: &dyn Fn(&str) -> bool| {
        let n = present.iter().filter(|v| pred(v)).count();
        n * 10 >= present.len() * 9
    };
    let tz = super::TzAssumption::Fixed(FixedOffset::east_opt(0).expect("zero offset"));
    match kind {
        TokenKind::Bracketed => {
            t.time_clf = most(&|v| timestamp::parse_clf_time(v).is_some());
            t.time_other = !t.time_clf && most(&|v| access::parse_time_text(v, &tz).is_some());
        }
        TokenKind::Quoted => {
            t.request = most(&|v| {
                let r = access::parse_request_line(v);
                r.method.is_some() && r.target.is_some() && r.version.is_some()
            });
            t.path = most(&|v| v.starts_with('/') || v == "*");
            t.url_or_dash = most(&is_url);
            t.user_agent = most(&|v| {
                v.chars().any(|c| c.is_ascii_alphabetic()) && !is_url(v) && !v.starts_with('/')
            }) && !t.request;
        }
        TokenKind::Bare => {
            t.method = most(&|v| access::is_http_method(v) && v.len() <= 16)
                && present
                    .iter()
                    .filter(|v| COMMON_METHODS.contains(v))
                    .count()
                    * 2
                    >= present.len();
            t.protocol = most(&access::is_http_version);
            t.status =
                most(&|v| v.len() == 3 && v.parse::<u16>().is_ok_and(|n| (100..600).contains(&n)));
            t.ip = most(&is_ip_list);
            t.integer = most(&|v| v.chars().all(|c| c.is_ascii_digit()));
            t.epoch = most(&|v| {
                v.len() >= 12
                    && v.split_once('.').is_some_and(|(s, f)| {
                        s.len() == 10
                            && s.chars().all(|c| c.is_ascii_digit())
                            && f.chars().all(|c| c.is_ascii_digit())
                    })
            });
            t.iso_time = most(&|v| timestamp::parse_iso_with_zone(v).is_some());
            t.path = most(&|v| v.starts_with('/'));
            t.hostname = most(&is_hostname);
        }
    }
    t
}

/// Work out the layout of an access log from sampled entry lines (amendment A21): the columns
/// must hold a timestamp, a request (one quoted request line, or method + path), a status, a
/// client IP and a user agent. `None` when they do not, or when the lines disagree on the shape.
pub fn infer_access_layout(lines: &[&str], product: Option<&'static str>) -> Option<Layout> {
    let tokenized: Vec<Vec<(TokenKind, &str)>> = lines.iter().filter_map(|l| tokenize(l)).collect();
    let mut shapes: HashMap<Vec<TokenKind>, usize> = HashMap::new();
    for t in &tokenized {
        *shapes
            .entry(t.iter().map(|(k, _)| *k).collect())
            .or_default() += 1;
    }
    let (shape, count) = shapes.into_iter().max_by_key(|(s, n)| (*n, s.len()))?;
    // most sampled lines must share one shape
    if count * 10 < lines.len() * 8 || (count < 3 && count < lines.len()) {
        return None;
    }
    let rows: Vec<&Vec<(TokenKind, &str)>> = tokenized
        .iter()
        .filter(|t| t.iter().map(|(k, _)| *k).eq(shape.iter().copied()))
        .collect();
    let traits: Vec<ColumnTraits> = (0..shape.len())
        .map(|c| {
            let values: Vec<&str> = rows.iter().map(|r| r[c].1).collect();
            column_traits(&values, shape[c])
        })
        .collect();
    let mut names: Vec<Option<&str>> = vec![None; shape.len()];
    let first = |pred: &dyn Fn(usize) -> bool, from: usize, names: &[Option<&str>]| {
        (from..shape.len()).find(|&c| names[c].is_none() && pred(c))
    };

    let time = first(
        &|c| traits[c].time_clf || traits[c].time_other || traits[c].iso_time || traits[c].epoch,
        0,
        &names,
    )?;
    names[time] = Some(if traits[time].time_clf {
        "time_local"
    } else if traits[time].iso_time {
        "time_iso8601"
    } else if traits[time].epoch {
        "msec"
    } else {
        "time"
    });

    let (request_start, request_end) = if let Some(r) = first(&|c| traits[c].request, 0, &names) {
        names[r] = Some("request");
        (r, r)
    } else {
        let method = first(&|c| traits[c].method, 0, &names)?;
        names[method] = Some("request_method");
        let uri = first(&|c| traits[c].path, method + 1, &names)?;
        names[uri] = Some("request_uri");
        match first(&|c| traits[c].protocol, uri + 1, &names) {
            Some(p) => {
                names[p] = Some("server_protocol");
                (method, p)
            }
            None => (method, uri),
        }
    };
    let status = first(&|c| traits[c].status, request_end + 1, &names)?;
    names[status] = Some("status");
    let ip = first(&|c| traits[c].ip, 0, &names)?;
    names[ip] = Some("remote_addr");
    let ua = first(
        &|c| shape[c] == TokenKind::Quoted && traits[c].user_agent,
        status + 1,
        &names,
    )?;
    names[ua] = Some("http_user_agent");
    if let Some(r) = (status + 1..ua)
        .find(|&c| names[c].is_none() && shape[c] == TokenKind::Quoted && traits[c].url_or_dash)
    {
        names[r] = Some("http_referer");
    }
    if let Some(b) = first(
        &|c| shape[c] == TokenKind::Bare && traits[c].integer,
        status + 1,
        &names,
    ) {
        names[b] = Some("body_bytes_sent");
    }
    // the virtual host: a host name column before the request
    if let Some(h) = (0..request_start).find(|&c| names[c].is_none() && traits[c].hostname) {
        names[h] = Some("host");
    }
    // CLF's `ident authuser` between the client and the time
    let between: Vec<usize> = (ip + 1..time).filter(|&c| names[c].is_none()).collect();
    match between.as_slice() {
        [user] => names[*user] = Some("remote_user"),
        [ident, user] => {
            names[*ident] = Some("ident");
            names[*user] = Some("remote_user");
        }
        _ => {}
    }

    let display = shape
        .iter()
        .enumerate()
        .map(|(c, kind)| {
            let var = match names[c] {
                Some(n) => format!("${n}"),
                None => format!("$field{}", c + 1),
            };
            match kind {
                TokenKind::Bare => var,
                TokenKind::Quoted => format!("\"{var}\""),
                TokenKind::Bracketed => format!("[{var}]"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let compiled = compile_nginx(&display).ok()?;
    let regex = Regex::new(&compiled.regex).ok()?;
    let matching = lines.iter().filter(|l| regex.is_match(l)).count();
    if matching * 10 < lines.len() * 8 {
        return None;
    }
    Some(Layout {
        name: "access-auto".to_string(),
        origin: Origin::Auto,
        kind: Kind::Webserver { product },
        regex,
        columns: compiled.columns,
        time_format: None,
        files: Vec::new(),
        display,
    })
}

// ------------------------------------------------------------------------------------------------
// Parser
// ------------------------------------------------------------------------------------------------

/// Events of a log source other than `webserver` from a regex format.
struct OtherBuilder {
    ctx: ParseContext,
    tag: LogSourceTag,
    time_format: Option<String>,
    last_ts: Option<DateTime<FixedOffset>>,
    warned_resolution: bool,
}

impl OtherBuilder {
    fn continuation(&self, line: &str) -> ParsedEvent {
        let mut ev = continuation_event(line, &self.tag, &[], self.last_ts);
        self.ctx.finish(&mut ev);
        ev
    }

    fn event(&mut self, line: &str, fields: Vec<(String, FieldValue)>) -> ParsedEvent {
        let mut ev = ParsedEvent::new(line, &self.tag);
        match access::record_timestamp(&fields, &self.ctx.tz, self.time_format.as_deref()) {
            Some((dt, explicit, res)) => {
                access::warn_resolution(&self.ctx, &mut self.warned_resolution, res);
                ev.timestamp = Some(dt);
                ev.tz_explicit = explicit && res == Resolution::Exact;
                self.last_ts = Some(dt);
            }
            None => {
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }
        for (key, value) in fields {
            // the time is the Timestamp column
            if access::TIME_KEYS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(&key))
            {
                continue;
            }
            let value = match value {
                FieldValue::Str(s) if is_dash(&s) => FieldValue::Null,
                other => other,
            };
            if matches!(key.as_str(), "hostname" | "host" | "computer")
                && let FieldValue::Str(h) = &value
            {
                ev.hostname = Some(h.clone());
            }
            ev.push(&key, value);
        }
        self.ctx.finish(&mut ev);
        ev
    }
}

enum Builder {
    Web(RecordBuilder),
    Other(OtherBuilder),
}

/// The line parser of a layout.
pub struct LayoutParser {
    layout: Arc<Layout>,
    builder: Builder,
}

impl LayoutParser {
    pub fn new(layout: Arc<Layout>, ctx: ParseContext) -> Self {
        let builder = match layout.kind {
            Kind::Webserver { product } => {
                // the format's product (nginx, apache), otherwise the path's
                let tags = access::product_tags(product.or(ctx.hints.product));
                Builder::Web(RecordBuilder::new(
                    ctx,
                    tags,
                    layout.time_format.clone(),
                    true,
                ))
            }
            Kind::Other { tag } => Builder::Other(OtherBuilder {
                ctx,
                tag,
                time_format: layout.time_format.clone(),
                last_ts: None,
                warned_resolution: false,
            }),
        };
        Self { layout, builder }
    }
}

impl LineParser for LayoutParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        let fields = self.layout.fields(line);
        Some(match (&mut self.builder, fields) {
            (Builder::Web(b), Some(f)) => b.event(line, f),
            (Builder::Web(b), None) => b.continuation(line),
            (Builder::Other(b), Some(f)) => b.event(line, f),
            (Builder::Other(b), None) => b.continuation(line),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::TzAssumption;

    fn utc() -> TzAssumption {
        TzAssumption::Fixed(FixedOffset::east_opt(0).expect("zero offset"))
    }

    fn ctx(path: &str) -> ParseContext {
        ParseContext::new(Path::new(path), utc())
    }

    fn names(c: &Compiled) -> Vec<&str> {
        c.columns
            .iter()
            .map(|c| c.as_ref().map_or("?", |c| c.name.as_str()))
            .collect()
    }

    fn registry(yaml: &str) -> FormatRegistry {
        FormatRegistry::parse(yaml).unwrap_or_else(|e| panic!("{e}"))
    }

    fn parse(layout: &Arc<Layout>, path: &str, line: &str) -> ParsedEvent {
        LayoutParser::new(Arc::clone(layout), ctx(path))
            .parse_line(line)
            .expect("a non-blank line is an event")
    }

    fn field<'a>(ev: &'a ParsedEvent, key: &str) -> &'a FieldValue {
        ev.field(key)
            .unwrap_or_else(|| panic!("field {key} missing from {:?}", ev.fields))
    }

    fn s(v: &str) -> FieldValue {
        FieldValue::Str(v.to_string())
    }

    const SPLIT_LAYOUT: &str = r#"[$time_local] $remote_addr $host $request_method $request_uri $server_protocol $status $body_bytes_sent $field9 "$http_referer" "$http_user_agent""#;

    const SPLIT_LINES: &[&str] = &[
        r#"[24/Oct/2026:15:35:32 +0000] 192.0.2.10 www.example.com POST /?q0000000=v&q0000001=v HTTP/2.0 200 149 0.512 "-" "Mozilla/5.0 (X11; Linux x86_64)""#,
        r#"[24/Oct/2026:15:35:33 +0000] 198.51.100.7 www.example.com GET /login.php HTTP/2.0 200 4521 0.040 "https://www.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)""#,
        r#"[24/Oct/2026:15:35:34 +0000] 203.0.113.5 www.example.com GET /static/app.css HTTP/2.0 304 0 0.000 "https://www.example.com/login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)""#,
        r#"[24/Oct/2026:15:35:35 +0000] 192.0.2.10 www.example.com POST /?q0000000=v&q0000001=v HTTP/2.0 200 149 0.498 "-" "curl/8.5.0""#,
    ];

    // ----- nginx ---------------------------------------------------------------------------

    #[test]
    fn nginx_variables_become_fields_and_quotes_and_brackets_shape_the_regex() {
        let c = compile_nginx(
            r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "${http_user_agent}""#,
        )
        .unwrap();
        assert_eq!(
            names(&c),
            [
                "remote_addr",
                "remote_user",
                "time_local",
                "request",
                "status",
                "body_bytes_sent",
                "http_referer",
                "http_user_agent"
            ]
        );
        let quoted: Vec<bool> = c
            .columns
            .iter()
            .map(|c| c.as_ref().unwrap().quoted)
            .collect();
        assert_eq!(
            quoted,
            [false, false, false, true, false, false, true, true]
        );
        let re = Regex::new(&c.regex).unwrap();
        let caps = re
            .captures(r#"192.0.2.1 - - [24/Oct/2026:15:35:32 +0000] "GET /a\"b HTTP/1.1" 200 5 "-" "UA x""#)
            .expect("combined line matches");
        assert_eq!(&caps[3], "24/Oct/2026:15:35:32 +0000");
        assert_eq!(&caps[4], r#"GET /a\"b HTTP/1.1"#);
        assert_eq!(&caps[8], "UA x");
    }

    #[test]
    fn nginx_directive_parts_are_joined_and_time_local_keeps_its_space() {
        let c = compile_nginx(
            "log_format main escape=default '$time_local $remote_addr '\n  '\"$request\" $status';",
        )
        .unwrap();
        assert_eq!(
            names(&c),
            ["time_local", "remote_addr", "request", "status"]
        );
        let re = Regex::new(&c.regex).unwrap();
        assert!(re.is_match(r#"24/Oct/2026:15:35:32 +0000 192.0.2.1 "GET / HTTP/1.1" 200"#));
        // a dollar without a name is literal text; repeated names are numbered
        let c = compile_nginx("$status $ $status").unwrap();
        assert_eq!(names(&c), ["status", "status_2"]);
        assert!(Regex::new(&c.regex).unwrap().is_match("200 $ 404"));
        assert!(compile_nginx("no variables").is_err());
    }

    // ----- Apache --------------------------------------------------------------------------

    #[test]
    fn apache_directives_map_to_the_nginx_names() {
        let c = compile_apache(
            r#"%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D %%"#,
        )
        .unwrap();
        assert_eq!(
            names(&c),
            [
                "host",
                "server_port",
                "remote_addr",
                "ident",
                "remote_user",
                "time_local",
                "request",
                "status",
                "bytes_sent",
                "http_referer",
                "http_user_agent",
                "request_time_us"
            ]
        );
        let re = Regex::new(&c.regex).unwrap();
        let caps = re
            .captures(r#"www.example.com:443 192.0.2.1 - bob [24/Oct/2026:15:35:32 +0900] "GET / HTTP/1.1" 200 512 "-" "curl/8.5.0" 1234 %"#)
            .expect("vhost_combined line matches");
        assert_eq!(
            &caps[6], "24/Oct/2026:15:35:32 +0900",
            "brackets are not part of the value"
        );
        assert_eq!(&caps[11], "curl/8.5.0");
    }

    #[test]
    fn apache_logformat_directive_and_custom_time_format() {
        let c =
            compile_apache(r#"LogFormat "%{%Y-%m-%d %H:%M:%S}t %a \"%r\" %s %b" mine"#).unwrap();
        assert_eq!(
            names(&c),
            [
                "time",
                "remote_addr",
                "request",
                "status",
                "body_bytes_sent"
            ]
        );
        assert_eq!(c.time_format.as_deref(), Some("%Y-%m-%d %H:%M:%S"));
        let re = Regex::new(&c.regex).unwrap();
        let caps = re
            .captures(r#"2026-10-24 15:35:32 192.0.2.1 "GET / HTTP/1.1" 200 5"#)
            .unwrap();
        assert_eq!(&caps[1], "2026-10-24 15:35:32");
        // epoch times need no format; begin:/end: prefixes are dropped
        assert_eq!(compile_apache("%{msec}t %s").unwrap().time_format, None);
        assert_eq!(
            compile_apache("%{end:%d/%b/%Y}t %s")
                .unwrap()
                .time_format
                .as_deref(),
            Some("%d/%b/%Y")
        );
        assert!(compile_apache("%h %Z").unwrap_err().contains("%Z"));
        assert!(compile_apache("%{Referer").is_err());
    }

    // ----- regex ---------------------------------------------------------------------------

    #[test]
    fn regex_groups_are_fields_and_taxonomy_names_get_their_hyphens() {
        let c = compile_regex(r"^(?P<c_ip>\S+) (\S+) (?P<sc_status>\d+) (?P<request_time>\S+)$")
            .unwrap();
        assert_eq!(names(&c), ["c-ip", "?", "sc-status", "request_time"]);
        assert!(compile_regex(r"^(\S+)$").is_err());
        assert!(
            compile_regex(r"^(?P<a>")
                .unwrap_err()
                .starts_with("invalid regex")
        );
    }

    // ----- configuration -------------------------------------------------------------------

    #[test]
    fn the_shipped_configuration_has_no_formats() {
        assert!(registry(DEFAULT_CUSTOM_FORMATS).is_empty());
        assert!(registry("").is_empty());
        assert!(registry("# only comments\n\n").is_empty());
        assert!(registry("formats:\n").is_empty());
    }

    #[test]
    fn configuration_errors_name_the_format() {
        let err = |yaml: &str| FormatRegistry::parse(yaml).unwrap_err();
        assert!(err("formats:\n  - name: a\n").contains("exactly one of nginx, apache or regex"));
        assert!(
            err("formats:\n  - name: a\n    nginx: '$status'\n    apache: '%s'\n")
                .contains("format \"a\"")
        );
        assert!(err("formats:\n  - name: syslog\n    nginx: '$status'\n").contains("built-in"));
        assert!(err("formats:\n  - name: ' '\n    nginx: '$status'\n").contains("empty"));
        assert!(
            err("formats:\n  - name: a\n    nginx: '$status'\n  - name: a\n    nginx: '$status'\n")
                .contains("twice")
        );
        assert!(
            err("formats:\n  - name: a\n    nginx: '$status'\n    logsource: {category: webserver}\n")
                .contains("only used with regex")
        );
        assert!(
            err(
                "formats:\n  - name: a\n    regex: '(?P<m>.*)'\n    logsource: {product: windows}\n"
            )
            .contains("unsupported logsource")
        );
        assert!(
            err("formats:\n  - name: a\n    nginx: '$status'\n    colour: red\n")
                .contains("colour")
        );
        assert!(
            err("formats:\n  - name: a\n    nginx: '$status'\n    files: ['[']\n")
                .contains("files")
        );
    }

    #[test]
    fn regex_logsources_pick_the_kind() {
        let r = registry(
            "formats:\n  - name: web\n    regex: '(?P<status>\\d+)'\n    logsource: {product: Apache, category: webserver}\n  - name: auth\n    regex: '(?P<message>.*)'\n    logsource: {product: linux, service: auth}\n  - name: plain\n    regex: '(?P<status>\\d+)'\n",
        );
        assert_eq!(
            r.get("web").unwrap().kind,
            Kind::Webserver {
                product: Some("apache")
            }
        );
        assert_eq!(
            r.get("custom:auth").unwrap().kind,
            Kind::Other {
                tag: LogSourceTag::LINUX_AUTH
            }
        );
        assert_eq!(
            r.get("plain").unwrap().kind,
            Kind::Webserver { product: None }
        );
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn files_patterns_match_the_file_name_or_with_a_slash_the_path() {
        let r = registry(
            "formats:\n  - name: a\n    nginx: '$status'\n    files: ['access.log*']\n  - name: b\n    nginx: '$status'\n    files: ['*/shop/*.log']\n  - name: c\n    nginx: '$status'\n",
        );
        let a = r.get("a").unwrap();
        assert!(a.has_file_filter());
        assert!(a.applies_to(Path::new("/var/log/nginx/access.log-20261024.gz")));
        assert!(!a.applies_to(Path::new("/var/log/nginx/error.log")));
        let b = r.get("b").unwrap();
        assert!(b.applies_to(Path::new("/srv/shop/x.log")));
        assert!(!b.applies_to(Path::new("/srv/blog/x.log")));
        assert!(r.get("c").unwrap().applies_to(Path::new("anything")));
    }

    // ----- parsing -------------------------------------------------------------------------

    #[test]
    fn a_custom_nginx_line_maps_to_the_webserver_taxonomy() {
        let r = registry(&format!(
            "formats:\n  - name: split\n    nginx: '{SPLIT_LAYOUT}'\n"
        ));
        let layout = r.get("split").unwrap();
        let ev = parse(&layout, "/var/log/www/site.log", SPLIT_LINES[0]);
        assert_eq!(ev.primary_logsource, "webserver");
        assert!(
            ev.tags.contains(&LogSourceTag::NGINX_WEBSERVER),
            "an nginx format is nginx"
        );
        assert_eq!(
            ev.timestamp.unwrap().to_rfc3339(),
            "2026-10-24T15:35:32+00:00"
        );
        assert!(ev.tz_explicit);
        assert_eq!(field(&ev, "c-ip"), &s("192.0.2.10"));
        assert_eq!(field(&ev, "cs-method"), &s("POST"));
        assert_eq!(field(&ev, "cs-uri-query"), &s("/?q0000000=v&q0000001=v"));
        assert_eq!(field(&ev, "cs-uri-stem"), &s("/"));
        assert_eq!(field(&ev, "cs-version"), &s("HTTP/2.0"));
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        assert_eq!(field(&ev, "sc-bytes"), &FieldValue::Int(149));
        assert_eq!(field(&ev, "cs-referer"), &FieldValue::Null);
        assert_eq!(
            field(&ev, "cs-user-agent"),
            &s("Mozilla/5.0 (X11; Linux x86_64)")
        );
        assert_eq!(field(&ev, "cs-host"), &s("www.example.com"));
        // the mapped columns and the time are not repeated; the rest keep their names
        for gone in [
            "remote_addr",
            "status",
            "time_local",
            "http_user_agent",
            "host",
        ] {
            assert!(ev.field(gone).is_none(), "{gone}");
        }
        assert_eq!(field(&ev, "field9"), &s("0.512"));
    }

    #[test]
    fn non_matching_lines_are_continuations_and_empty_values_still_match() {
        let r = registry(&format!(
            "formats:\n  - name: split\n    nginx: '{SPLIT_LAYOUT}'\n"
        ));
        let layout = r.get("split").unwrap();
        let mut p = LayoutParser::new(Arc::clone(&layout), ctx("/var/log/www/site.log"));
        let first = p.parse_line(SPLIT_LINES[0]).unwrap();
        // an empty $host leaves two spaces
        let ev = p
            .parse_line(
                r#"[24/Oct/2026:15:35:36 +0000] 192.0.2.99  GET - HTTP/1.1 400 157 - "-" "-""#,
            )
            .unwrap();
        assert_eq!(field(&ev, "c-ip"), &s("192.0.2.99"));
        assert_eq!(field(&ev, "cs-host"), &FieldValue::Null);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(400));
        assert_eq!(field(&ev, "field9"), &FieldValue::Null, "- is null");
        let cont = p.parse_line("stray text").unwrap();
        assert_eq!(cont.fields, vec![("message".to_string(), s("stray text"))]);
        assert!(cont.timestamp_inferred);
        assert!(cont.timestamp > first.timestamp);
        assert!(p.parse_line("   ").is_none());
    }

    #[test]
    fn a_regex_format_for_another_logsource_keeps_its_field_names() {
        let r = registry(
            "formats:\n  - name: vpnd\n    regex: '^(?P<timestamp>\\S+ \\S+) (?P<hostname>\\S+) (?P<process>\\w+)\\[(?P<pid>\\d+)\\]: (?P<message>.*)$'\n    time_format: '%Y-%m-%d %H:%M:%S'\n    logsource: {product: linux, service: sshd}\n",
        );
        let layout = r.get("vpnd").unwrap();
        let ev = parse(
            &layout,
            "/var/log/vpnd.log",
            "2026-10-26 09:00:05 bastion01 vpnd[812]: Corrupted MAC on input",
        );
        assert_eq!(ev.primary_logsource, "linux/sshd");
        assert_eq!(ev.tags, vec![LogSourceTag::LINUX_SSHD]);
        assert_eq!(
            ev.timestamp.unwrap().to_rfc3339(),
            "2026-10-26T09:00:05+00:00"
        );
        assert!(!ev.tz_explicit, "a time without a zone is read in -z");
        assert_eq!(ev.hostname.as_deref(), Some("bastion01"));
        let keys: Vec<&str> = ev.fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["hostname", "process", "pid", "message"]);
        // a line the regex does not match borrows the previous time
        let mut p = LayoutParser::new(layout, ctx("/var/log/vpnd.log"));
        p.parse_line("2026-10-26 09:00:05 bastion01 vpnd[812]: x")
            .unwrap();
        let cont = p.parse_line("  continued").unwrap();
        assert_eq!(cont.primary_logsource, "linux/sshd");
        assert!(cont.timestamp_inferred);
    }

    #[test]
    fn time_formats_with_and_without_a_zone() {
        let r = registry(
            "formats:\n  - name: a\n    regex: '^(?P<time>.+?) (?P<status>\\d+)$'\n    time_format: '%d.%m.%Y %H:%M:%S %z'\n",
        );
        let ev = parse(
            &r.get("a").unwrap(),
            "/x.log",
            "24.10.2026 15:35:32 +0900 200",
        );
        assert_eq!(
            ev.timestamp.unwrap().to_rfc3339(),
            "2026-10-24T15:35:32+09:00"
        );
        assert!(ev.tz_explicit);
        assert_eq!(field(&ev, "sc-status"), &FieldValue::Int(200));
        let ev = parse(&r.get("a").unwrap(), "/x.log", "yesterday 200");
        assert_eq!(
            ev.timestamp, None,
            "an unparsable time leaves the event without one"
        );
    }

    // ----- automatic detection -------------------------------------------------------------

    #[test]
    fn tokens_keep_quotes_and_brackets_whole() {
        let t = tokenize(r#"a "b \" c" [d e] -"#).unwrap();
        assert_eq!(
            t,
            vec![
                (TokenKind::Bare, "a"),
                (TokenKind::Quoted, r#"b \" c"#),
                (TokenKind::Bracketed, "d e"),
                (TokenKind::Bare, "-"),
            ]
        );
        assert!(tokenize(r#"a "unterminated"#).is_none());
        assert!(tokenize(r#""glued"x"#).is_none());
    }

    #[test]
    fn a_split_request_layout_is_detected_and_printed_as_an_nginx_format() {
        let layout = infer_access_layout(SPLIT_LINES, None).expect("detected");
        assert_eq!(layout.origin, Origin::Auto);
        assert_eq!(layout.format_name(), "access-auto");
        assert_eq!(layout.display, SPLIT_LAYOUT);
        // pasting the printed layout into the configuration reads the same fields
        let pinned = registry(&format!(
            "formats:\n  - name: p\n    nginx: '{}'\n",
            layout.display
        ));
        let auto = Arc::new(layout);
        let a = parse(&auto, "/var/log/site.log", SPLIT_LINES[1]);
        let b = parse(
            &pinned.get("p").unwrap(),
            "/var/log/site.log",
            SPLIT_LINES[1],
        );
        assert_eq!(a.fields, b.fields);
        assert_eq!(a.timestamp, b.timestamp);
        // the product comes from the path, as for the built-in access logs
        let ev = parse(&auto, "/var/log/apache2/site.log", SPLIT_LINES[1]);
        assert!(ev.tags.contains(&LogSourceTag::APACHE_WEBSERVER));
        let ev = parse(&auto, "/logs/site.log", SPLIT_LINES[1]);
        assert_eq!(ev.tags, vec![LogSourceTag::WEBSERVER]);
        let apache = Arc::new(infer_access_layout(SPLIT_LINES, Some("apache")).unwrap());
        let ev = parse(&apache, "/logs/site.log", SPLIT_LINES[1]);
        assert!(ev.tags.contains(&LogSourceTag::APACHE_WEBSERVER));
    }

    #[test]
    fn other_common_layouts_are_detected() {
        // combined with a leading vhost without a port and a trailing request time
        let lines = [
            r#"shop.example.com 192.0.2.1 - - [24/Oct/2026:15:35:32 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.5.0" 0.004"#,
            r#"shop.example.com 192.0.2.2 - alice [24/Oct/2026:15:35:33 +0000] "POST /login HTTP/1.1" 302 0 "https://shop.example.com/" "Mozilla/5.0 (X11)" 0.120"#,
            r#"shop.example.com 192.0.2.3 - - [24/Oct/2026:15:35:34 +0000] "GET /x HTTP/1.1" 404 0 "-" "Mozilla/5.0 (X11)" 0.001"#,
        ];
        let l = infer_access_layout(&lines, None).unwrap();
        assert_eq!(
            l.display,
            r#"$host $remote_addr $ident $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $field11"#
        );
        // ISO 8601 time first, unquoted path, user agent last
        let lines = [
            r#"2026-10-24T15:35:32+09:00 192.0.2.1 GET /a HTTP/1.1 200 "Mozilla/5.0 (X11)""#,
            r#"2026-10-24T15:35:33+09:00 192.0.2.2 POST /b HTTP/2.0 500 "curl/8.5.0""#,
            r#"2026-10-24T15:35:34+09:00 192.0.2.3 GET /c HTTP/1.1 301 "Mozilla/5.0 (X11)""#,
        ];
        let l = infer_access_layout(&lines, None).unwrap();
        assert_eq!(
            l.display,
            r#"$time_iso8601 $remote_addr $request_method $request_uri $server_protocol $status "$http_user_agent""#
        );
        // nginx $msec
        let lines = [
            r#"1792856132.123 192.0.2.1 "GET / HTTP/1.1" 200 "-" "curl/8.5.0""#,
            r#"1792856133.456 192.0.2.2 "GET /x HTTP/1.1" 404 "-" "curl/8.5.0""#,
            r#"1792856134.789 192.0.2.3 "HEAD / HTTP/1.1" 200 "-" "Mozilla/5.0 (X11)""#,
        ];
        let l = infer_access_layout(&lines, None).unwrap();
        assert!(
            l.display
                .starts_with("$msec $remote_addr \"$request\" $status"),
            "{}",
            l.display
        );
        let ev = parse(&Arc::new(l), "/x.log", lines[0]);
        assert_eq!(ev.timestamp.unwrap().timestamp(), 1_792_856_132);
    }

    #[test]
    fn logs_without_the_key_columns_are_not_access_logs() {
        // a health-check log: time, IP, method, path and status, but no user agent
        let health = [
            r#"[24/Oct/2026:15:35:32 +0000] 192.0.2.10 GET "/healthz" HTTP/1.1 200 0.002"#,
            r#"[24/Oct/2026:15:35:42 +0000] 192.0.2.10 GET "/healthz" HTTP/1.1 200 0.001"#,
            r#"[24/Oct/2026:15:35:52 +0000] 192.0.2.11 GET "/readyz" HTTP/1.1 503 0.004"#,
        ];
        assert!(infer_access_layout(&health, None).is_none());
        // no status
        let audit = [
            r#"[24/Oct/2026:04:01:34 +0000] 192.0.2.10 "GET /a HTTP/1.1" "Mozilla/5.0 (X11)" app1"#,
            r#"[24/Oct/2026:04:01:35 +0000] 192.0.2.11 "GET /b HTTP/1.1" "Mozilla/5.0 (X11)" app2"#,
            r#"[24/Oct/2026:05:10:27 +0000] 192.0.2.12 "POST /c HTTP/2.0" "curl/8.5.0" app1"#,
        ];
        assert!(infer_access_layout(&audit, None).is_none());
        // syslog
        let syslog = [
            "Oct 24 15:35:32 host sshd[1]: Accepted publickey for root from 192.0.2.1 port 22 ssh2",
            "Oct 24 15:35:33 host sshd[1]: Received disconnect from 192.0.2.1 port 22",
            "Oct 24 15:35:34 host CRON[2]: (root) CMD (true)",
        ];
        assert!(infer_access_layout(&syslog, None).is_none());
        // lines that disagree on the shape
        let mixed = [SPLIT_LINES[0], SPLIT_LINES[1], "a b c", "d e f", "g h i"];
        assert!(infer_access_layout(&mixed, None).is_none());
        assert!(infer_access_layout(&[], None).is_none());
    }
}
