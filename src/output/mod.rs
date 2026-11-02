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

//! Output: profiles, row rendering, and the stdout / CSV / JSON / JSONL writers (design §9,
//! amendment A15).
//!
//! A detection (or a fired correlation) is rendered once into a [`Row`] of [`Cell`]s, one per
//! column of the selected profile. The terminal and CSV outputs flatten structured cells
//! (`Key: value ¦ Key: value`, lists joined with ` ¦ `, absent values as `-`); JSON and JSONL keep
//! the structure (objects with the keys in parsed order, arrays, numbers, `null`). Every string
//! that reaches an output has passed [`sanitize_control_chars`], and CSV cells additionally pass
//! [`sanitize_csv_field`] (CWE-1236), like Suzaku.

pub mod tags;

use crate::cli::OutputFormat;
use crate::color::IwatobiColor;
use crate::correlate::{BaseHit, CorrelationHit};
use crate::detect::Detection;
use crate::event::FieldValue;
use crate::rules::RuleMeta;
use crate::util::{sanitize_control_chars, sanitize_csv_field};
use chrono::{DateTime, Local, Utc};
use serde_json::Value as JsonValue;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tags::{SplitTags, TacticTable};
use termcolor::{Buffer, BufferWriter, ColorChoice, ColorSpec, WriteColor};

/// Embedded default profiles.
pub const DEFAULT_PROFILES: &str = include_str!("../../config/profiles.yaml");

/// Column separator of the terminal output (space, middle dot U+00B7, space), as in Hayabusa and
/// Suzaku.
pub const COLUMN_SEPARATOR: &str = " · ";
/// Separator between the entries of a structured cell in the terminal and CSV output (space,
/// broken bar U+00A6, space).
pub const ENTRY_SEPARATOR: &str = " ¦ ";
/// Text of an absent value in the terminal and CSV output.
pub const EMPTY: &str = "-";

/// The tactic abbreviation table, loaded once per run. A `config/mitre_tactics.txt` in the current
/// directory or next to the executable overrides the embedded copy.
static TACTIC_TABLE: LazyLock<TacticTable> = LazyLock::new(|| {
    TacticTable::parse(&crate::util::asset(
        "config/mitre_tactics.txt",
        tags::DEFAULT_MITRE_TACTICS,
    ))
});

/// What a profile column shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placeholder {
    Timestamp,
    RuleTitle,
    Level,
    Computer,
    LogSource,
    Details,
    RawLine,
    LineNumber,
    LogFile,
    MitreTactics,
    MitreTags,
    OtherTags,
    RuleFile,
    RuleID,
    RuleAuthor,
    RuleCreationDate,
    RuleModifiedDate,
    Status,
    Description,
    References,
    FalsePositives,
}

impl Placeholder {
    /// `%Timestamp%` → `Placeholder::Timestamp`.
    pub fn parse(spec: &str) -> Option<Placeholder> {
        let name = spec.trim().trim_matches('%');
        Some(match name {
            "Timestamp" => Placeholder::Timestamp,
            "RuleTitle" => Placeholder::RuleTitle,
            "Level" => Placeholder::Level,
            "Computer" => Placeholder::Computer,
            "LogSource" => Placeholder::LogSource,
            "Details" => Placeholder::Details,
            "RawLine" => Placeholder::RawLine,
            "LineNumber" => Placeholder::LineNumber,
            "LogFile" => Placeholder::LogFile,
            "MitreTactics" => Placeholder::MitreTactics,
            "MitreTags" => Placeholder::MitreTags,
            "OtherTags" => Placeholder::OtherTags,
            "RuleFile" => Placeholder::RuleFile,
            "RuleID" => Placeholder::RuleID,
            "RuleAuthor" => Placeholder::RuleAuthor,
            "RuleCreationDate" => Placeholder::RuleCreationDate,
            "RuleModifiedDate" => Placeholder::RuleModifiedDate,
            "Status" => Placeholder::Status,
            "Description" => Placeholder::Description,
            "References" => Placeholder::References,
            "FalsePositives" => Placeholder::FalsePositives,
            _ => return None,
        })
    }
}

/// An output profile: ordered columns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub columns: Vec<(String, Placeholder)>,
}

impl Profile {
    pub fn uses(&self, p: Placeholder) -> bool {
        self.columns.iter().any(|(_, c)| *c == p)
    }

    /// The column names, in order (the CSV header and the JSON keys).
    pub fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|(c, _)| c.as_str()).collect()
    }
}

/// Parse `config/profiles.yaml` (name → column → `%Placeholder%`), keeping column order.
///
/// `yaml_serde::Mapping` preserves the document order, so a profile's columns come out in the
/// order they are written. Every structural problem is an `Err` naming the profile (and column)
/// concerned, including an unknown placeholder.
pub fn parse_profiles(yaml: &str) -> Result<BTreeMap<String, Profile>, String> {
    let doc: yaml_serde::Value =
        yaml_serde::from_str(yaml).map_err(|e| format!("invalid YAML: {e}"))?;
    let top = match doc {
        yaml_serde::Value::Mapping(m) => m,
        yaml_serde::Value::Null => return Err("the file defines no profiles".to_string()),
        _ => {
            return Err("the file must be a mapping of profile names to their columns".to_string());
        }
    };
    let mut profiles = BTreeMap::new();
    for (key, value) in &top {
        let name = key
            .as_str()
            .ok_or_else(|| format!("profile names must be strings (found {})", describe(key)))?;
        let Some(cols) = value.as_mapping() else {
            return Err(format!(
                "profile '{name}' must be a mapping of column names to %Placeholder% values (found {})",
                describe(value)
            ));
        };
        let mut columns = Vec::with_capacity(cols.len());
        for (ck, cv) in cols {
            let col = ck.as_str().ok_or_else(|| {
                format!(
                    "profile '{name}': column names must be strings (found {})",
                    describe(ck)
                )
            })?;
            let spec = cv.as_str().ok_or_else(|| {
                format!(
                    "profile '{name}', column '{col}': the value must be a %Placeholder% string (found {})",
                    describe(cv)
                )
            })?;
            let placeholder = Placeholder::parse(spec).ok_or_else(|| {
                format!("profile '{name}', column '{col}': unknown placeholder '{spec}'")
            })?;
            columns.push((col.to_string(), placeholder));
        }
        if columns.is_empty() {
            return Err(format!("profile '{name}' has no columns"));
        }
        profiles.insert(
            name.to_string(),
            Profile {
                name: name.to_string(),
                columns,
            },
        );
    }
    if profiles.is_empty() {
        return Err("the file defines no profiles".to_string());
    }
    Ok(profiles)
}

fn describe(v: &yaml_serde::Value) -> &'static str {
    match v {
        yaml_serde::Value::Null => "null",
        yaml_serde::Value::Bool(_) => "a boolean",
        yaml_serde::Value::Number(_) => "a number",
        yaml_serde::Value::String(_) => "a string",
        yaml_serde::Value::Sequence(_) => "a list",
        yaml_serde::Value::Mapping(_) => "a mapping",
        yaml_serde::Value::Tagged(_) => "a tagged value",
    }
}

/// A rendered cell. CSV/stdout join structured values with ` ¦ `; JSON keeps the structure.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Text(String),
    Number(i64),
    Null,
    /// Ordered key/value pairs (Details).
    Map(Vec<(String, serde_json::Value)>),
    /// A list (tags, references, false positives).
    List(Vec<String>),
}

/// `--sort` key of a row: the event instant (None sorts last), then rule title, then file, then line.
pub type SortKey = (Option<DateTime<Utc>>, String, String, usize);

/// Order of two rows under `--sort`: by instant with unknown times last, then title, file, line.
pub fn compare_sort_keys(a: &SortKey, b: &SortKey) -> Ordering {
    a.0.is_none()
        .cmp(&b.0.is_none())
        .then_with(|| a.0.cmp(&b.0))
        .then_with(|| a.1.cmp(&b.1))
        .then_with(|| a.2.cmp(&b.2))
        .then_with(|| a.3.cmp(&b.3))
}

/// One output row.
#[derive(Clone, Debug)]
pub struct Row {
    /// For `--sort`: the event instant (None sorts last), then title, then file/line.
    pub sort_key: SortKey,
    pub level: String,
    pub cells: Vec<Cell>,
}

#[derive(Clone, Debug)]
pub struct RenderOptions {
    pub utc: bool,
}

// ------------------------------------------------------------------------------------------------
// Rendering
// ------------------------------------------------------------------------------------------------

/// Sanitized text cell.
fn text(s: &str) -> Cell {
    Cell::Text(sanitize_control_chars(s))
}

/// Sanitized text cell, `Null` for a missing or empty value.
fn opt_text(s: Option<&str>) -> Cell {
    match s {
        Some(s) if !s.is_empty() => text(s),
        _ => Cell::Null,
    }
}

fn sanitized_list(items: &[String]) -> Cell {
    Cell::List(items.iter().map(|s| sanitize_control_chars(s)).collect())
}

/// The tags of the rule split into the three columns, when the profile shows any of them.
fn profile_tags(profile: &Profile, meta: &RuleMeta) -> SplitTags {
    if profile.uses(Placeholder::MitreTactics)
        || profile.uses(Placeholder::MitreTags)
        || profile.uses(Placeholder::OtherTags)
    {
        TACTIC_TABLE.split(&meta.tags)
    } else {
        SplitTags::default()
    }
}

/// The cell of a rule-metadata placeholder (shared by detections and correlations). `None` for
/// the event placeholders.
fn rule_cell(placeholder: Placeholder, meta: &RuleMeta, tags: &SplitTags) -> Option<Cell> {
    Some(match placeholder {
        Placeholder::RuleTitle => text(&meta.title),
        Placeholder::Level => text(&meta.level.trim().to_ascii_lowercase()),
        Placeholder::MitreTactics => Cell::List(tags.tactics.clone()),
        Placeholder::MitreTags => Cell::List(tags.mitre.clone()),
        Placeholder::OtherTags => sanitized_list(&tags.other),
        Placeholder::RuleFile => opt_text(Some(meta.rule_file.as_str())),
        Placeholder::RuleID => opt_text(meta.id.as_deref()),
        Placeholder::RuleAuthor => opt_text(meta.author.as_deref()),
        Placeholder::RuleCreationDate => opt_text(meta.date.as_deref()),
        Placeholder::RuleModifiedDate => opt_text(meta.modified.as_deref()),
        Placeholder::Status => opt_text(meta.status.as_deref()),
        Placeholder::Description => opt_text(meta.description.as_deref()),
        Placeholder::References => sanitized_list(&meta.references),
        Placeholder::FalsePositives => sanitized_list(&meta.falsepositives),
        _ => return None,
    })
}

/// Human label of a parsed field in the Details cell.
pub fn field_label(key: &str) -> String {
    let label = match key {
        "process" => "Proc",
        "pid" => "PID",
        "message" => "Msg",
        "c-ip" => "SrcIP",
        "cs-method" => "Method",
        "cs-uri-query" => "URI",
        "sc-status" => "Status",
        "sc-bytes" => "Bytes",
        "cs-referer" => "Referer",
        "cs-user-agent" => "UA",
        "module" => "Module",
        "level" => "Level",
        "client" => "Client",
        "php_type" => "Type",
        "pool" => "Pool",
        "child_pid" => "ChildPID",
        "request" => "Request",
        "upstream" => "Upstream",
        // PHP's script location (`in /var/www/x.php on line 3`), not the log file and line,
        // which have their own LogFile / LineNumber columns.
        "file" => "PhpFile",
        "line" => "PhpLine",
        other => return sanitize_control_chars(other),
    };
    label.to_string()
}

/// JSON value of a parsed field (strings sanitized, numbers and null kept).
fn field_json(value: &FieldValue) -> JsonValue {
    match value {
        FieldValue::Str(s) => JsonValue::String(sanitize_control_chars(s)),
        other => other.to_json(),
    }
}

/// The ordered map of a field slice, with human labels, plus `TimestampInferred: true` when the
/// event borrowed its timestamp from the previous entry.
fn field_map(fields: &[(String, FieldValue)], inferred: bool) -> Vec<(String, JsonValue)> {
    // A label is used only when no other field of the event already has that name (a JSON access
    // log may carry its own `Method` or `SrcIP` key next to `cs-method` / `c-ip`), so the map
    // never holds the same key twice.
    let mut out: Vec<(String, JsonValue)> = Vec::with_capacity(fields.len() + 1);
    for (k, v) in fields {
        let label = field_label(k);
        let collides = label != *k
            && (fields.iter().any(|(other, _)| *other == label)
                || out.iter().any(|(used, _)| *used == label));
        let key = if collides {
            sanitize_control_chars(k)
        } else {
            label
        };
        out.push((key, field_json(v)));
    }
    if inferred {
        out.push(("TimestampInferred".to_string(), JsonValue::Bool(true)));
    }
    out
}

/// Render a detection with a profile.
pub fn render_detection(
    det: &Detection,
    meta: &RuleMeta,
    profile: &Profile,
    opts: &RenderOptions,
) -> Row {
    let event = &det.event;
    let time_utc = event.timestamp.map(|t| t.with_timezone(&Utc));
    let tags = profile_tags(profile, meta);
    let cells = profile
        .columns
        .iter()
        .map(|(_, placeholder)| match placeholder {
            Placeholder::Timestamp => {
                time_utc.map_or(Cell::Null, |t| Cell::Text(format_timestamp(&t, opts.utc)))
            }
            Placeholder::Computer => opt_text(event.hostname.as_deref()),
            Placeholder::LogSource => text(&event.primary_logsource),
            Placeholder::Details => Cell::Map(field_map(&event.fields, event.timestamp_inferred)),
            Placeholder::RawLine => text(&event.raw),
            Placeholder::LineNumber => Cell::Number(i64::try_from(det.line).unwrap_or(i64::MAX)),
            Placeholder::LogFile => opt_text(Some(&det.file)),
            other => rule_cell(*other, meta, &tags).unwrap_or(Cell::Null),
        })
        .collect();
    Row {
        sort_key: (time_utc, meta.title.clone(), det.file.to_string(), det.line),
        level: meta.level.clone(),
        cells,
    }
}

/// `RuleTitle (file:line)` → `RuleTitle` (a member summary as `detect.rs` builds it). Only a
/// trailing `(<file>:<digits>)` is stripped, so a title that itself ends in parentheses survives.
fn member_title(summary: &str) -> &str {
    match summary.rsplit_once(" (") {
        Some((title, rest)) if !title.is_empty() && is_location(rest) => title,
        _ => summary,
    }
}

/// `file.log:12)`: the location part of a member summary.
fn is_location(rest: &str) -> bool {
    rest.strip_suffix(')')
        .and_then(|r| r.rsplit_once(':'))
        .is_some_and(|(_, line)| !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()))
}

/// The Details map of a correlation row: `Count`, the distinct `Rules` (joined with `, `, as
/// design §8 writes them), `First`/`Last` member time, the `GroupBy` values when the
/// correlation groups, and the `Members` (`Rule title (file:line)` of each member event).
fn correlation_details(
    hit: &CorrelationHit,
    members: &[&BaseHit],
    opts: &RenderOptions,
) -> Vec<(String, JsonValue)> {
    let mut rules: Vec<String> = Vec::new();
    for member in members {
        let title = sanitize_control_chars(member_title(&member.summary));
        if !rules.contains(&title) {
            rules.push(title);
        }
    }
    let mut details = vec![
        (
            "Count".to_string(),
            JsonValue::from(u64::try_from(hit.count).unwrap_or(u64::MAX)),
        ),
        ("Rules".to_string(), JsonValue::String(rules.join(", "))),
        (
            "First".to_string(),
            JsonValue::String(format_timestamp(&hit.first, opts.utc)),
        ),
        (
            "Last".to_string(),
            JsonValue::String(format_timestamp(&hit.last, opts.utc)),
        ),
    ];
    if !hit.group_values.is_empty() {
        details.push((
            "GroupBy".to_string(),
            JsonValue::String(sanitize_control_chars(&hit.group_values.join(", "))),
        ));
    }
    details.push((
        "Members".to_string(),
        JsonValue::Array(
            members
                .iter()
                .map(|m| JsonValue::String(sanitize_control_chars(&m.summary)))
                .collect(),
        ),
    ));
    details
}

/// Render a correlation hit with a profile.
pub fn render_correlation(
    hit: &CorrelationHit,
    members: &[&BaseHit],
    meta: &RuleMeta,
    profile: &Profile,
    opts: &RenderOptions,
) -> Row {
    let tags = profile_tags(profile, meta);
    let details = correlation_details(hit, members, opts);
    let cells = profile
        .columns
        .iter()
        .map(|(_, placeholder)| match placeholder {
            Placeholder::Timestamp => Cell::Text(format_timestamp(&hit.timestamp, opts.utc)),
            Placeholder::Computer => opt_text(hit.hostname.as_deref()),
            Placeholder::LogSource => Cell::Text("correlation".to_string()),
            Placeholder::Details => Cell::Map(details.clone()),
            // A correlation spans several lines, often of several files: show the files, and leave
            // the line to the member list (`file:line` in Details).
            Placeholder::LogFile => member_files(members),
            Placeholder::RawLine | Placeholder::LineNumber => Cell::Null,
            other => rule_cell(*other, meta, &tags).unwrap_or(Cell::Null),
        })
        .collect();
    Row {
        sort_key: (Some(hit.timestamp), meta.title.clone(), String::new(), 0),
        level: meta.level.clone(),
        cells,
    }
}

/// The distinct log files of a correlation's members, in first-seen order.
fn member_files(members: &[&BaseHit]) -> Cell {
    let mut files: Vec<String> = Vec::new();
    for m in members {
        if !m.file.is_empty() && !files.iter().any(|f| f.as_str() == &*m.file) {
            files.push(sanitize_control_chars(&m.file));
        }
    }
    match files.len() {
        0 => Cell::Null,
        1 => Cell::Text(files.remove(0)),
        _ => Cell::List(files),
    }
}

/// Format a timestamp for the `Timestamp` column: `2026-10-24 15:35:38.673 +00:00`
/// (local time, or UTC with `-U`).
pub fn format_timestamp(t: &DateTime<Utc>, utc: bool) -> String {
    const FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f %:z";
    if utc {
        t.format(FORMAT).to_string()
    } else {
        t.with_timezone(&Local).format(FORMAT).to_string()
    }
}

// ------------------------------------------------------------------------------------------------
// Text (terminal / CSV) rendering
// ------------------------------------------------------------------------------------------------

/// Terminal/CSV text of a JSON value inside a structured cell: strings as they are, numbers as
/// digits, `null` as `-`, arrays joined with `, `.
fn json_text(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => EMPTY.to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(items) => items.iter().map(json_text).collect::<Vec<_>>().join(", "),
        JsonValue::Object(_) => value.to_string(),
    }
}

/// Terminal/CSV text of a cell: `Key: value ¦ Key: value` for maps, ` ¦ `-joined lists, `-` for
/// `Null` and for empty maps/lists, digits for numbers.
pub fn cell_text(cell: &Cell) -> String {
    match cell {
        Cell::Text(s) => s.clone(),
        Cell::Number(n) => n.to_string(),
        Cell::Null => EMPTY.to_string(),
        Cell::Map(pairs) if pairs.is_empty() => EMPTY.to_string(),
        Cell::Map(pairs) => pairs
            .iter()
            .map(|(k, v)| format!("{k}: {}", json_text(v)))
            .collect::<Vec<_>>()
            .join(ENTRY_SEPARATOR),
        Cell::List(items) if items.is_empty() => EMPTY.to_string(),
        Cell::List(items) => items.join(ENTRY_SEPARATOR),
    }
}

/// The cell of column `i`, `Null` when the row is short.
fn cell_at(row: &Row, i: usize) -> &Cell {
    row.cells.get(i).unwrap_or(&Cell::Null)
}

/// The text of every column of `row` for the terminal and the CSV file (the CSV writer adds its
/// own formula guard on top).
fn row_texts(profile: &Profile, row: &Row) -> Vec<String> {
    (0..profile.columns.len())
        .map(|i| cell_text(cell_at(row, i)))
        .collect()
}

/// Append the terminal rendering of `row` to `buf`: the column names once (uncolored, `header`),
/// then the row colored by its level with the columns joined by ` · `, then a blank line.
fn render_stdout(
    buf: &mut Buffer,
    profile: &Profile,
    row: &Row,
    header: bool,
    no_color: bool,
) -> io::Result<()> {
    if header {
        buf.reset()?;
        writeln!(buf, "{}", profile.column_names().join(COLUMN_SEPARATOR))?;
        writeln!(buf)?;
    }
    let color = IwatobiColor::for_level(&row.level).rdg(no_color);
    buf.set_color(ColorSpec::new().set_fg(color))?;
    write!(buf, "{}", row_texts(profile, row).join(COLUMN_SEPARATOR))?;
    buf.reset()?;
    writeln!(buf)?;
    writeln!(buf)
}

// ------------------------------------------------------------------------------------------------
// JSON rendering (keys in profile / field order: serde_json's `preserve_order` is not enabled)
// ------------------------------------------------------------------------------------------------

/// A JSON tree with ordered object keys.
enum JsonNode {
    /// Already-serialized scalar (`"text"`, `12`, `true`, `null`).
    Scalar(String),
    Array(Vec<JsonNode>),
    Object(Vec<(String, JsonNode)>),
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn json_node_of_value(value: &JsonValue) -> JsonNode {
    match value {
        JsonValue::Array(items) => JsonNode::Array(items.iter().map(json_node_of_value).collect()),
        JsonValue::Object(map) => JsonNode::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), json_node_of_value(v)))
                .collect(),
        ),
        scalar => JsonNode::Scalar(scalar.to_string()),
    }
}

fn json_node_of_cell(cell: &Cell) -> JsonNode {
    match cell {
        Cell::Text(s) => JsonNode::Scalar(json_string(s)),
        Cell::Number(n) => JsonNode::Scalar(n.to_string()),
        Cell::Null => JsonNode::Scalar("null".to_string()),
        Cell::Map(pairs) => JsonNode::Object(
            pairs
                .iter()
                .map(|(k, v)| (k.clone(), json_node_of_value(v)))
                .collect(),
        ),
        Cell::List(items) => JsonNode::Array(
            items
                .iter()
                .map(|s| JsonNode::Scalar(json_string(s)))
                .collect(),
        ),
    }
}

fn push_indent(out: &mut String, n: usize) {
    out.extend(std::iter::repeat_n(' ', n));
}

/// Serialize a node. `pretty` reproduces serde_json's pretty layout (two-space indent, one entry
/// per line, `[]`/`{}` for empty containers); otherwise the output is compact.
fn write_json_node(out: &mut String, node: &JsonNode, indent: usize, pretty: bool) {
    match node {
        JsonNode::Scalar(s) => out.push_str(s),
        JsonNode::Array(items) if items.is_empty() => out.push_str("[]"),
        JsonNode::Object(entries) if entries.is_empty() => out.push_str("{}"),
        JsonNode::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, indent + 2);
                }
                write_json_node(out, item, indent + 2, pretty);
            }
            if pretty {
                out.push('\n');
                push_indent(out, indent);
            }
            out.push(']');
        }
        JsonNode::Object(entries) => {
            out.push('{');
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, indent + 2);
                }
                out.push_str(&json_string(key));
                out.push_str(if pretty { ": " } else { ":" });
                write_json_node(out, value, indent + 2, pretty);
            }
            if pretty {
                out.push('\n');
                push_indent(out, indent);
            }
            out.push('}');
        }
    }
}

/// One row as a JSON object whose keys are the profile columns in order. `pretty` gives the
/// multi-line layout of the `json` output, otherwise the single-line `jsonl` form.
pub fn row_json(profile: &Profile, row: &Row, pretty: bool) -> String {
    let entries = profile
        .columns
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.clone(), json_node_of_cell(cell_at(row, i))))
        .collect();
    let mut out = String::new();
    write_json_node(&mut out, &JsonNode::Object(entries), 0, pretty);
    out
}

// ------------------------------------------------------------------------------------------------
// Output files
// ------------------------------------------------------------------------------------------------

/// The concrete output file paths for `-o` and the selected types (`<base>.<ext>` per type).
pub fn resolve_output_targets(
    output: &Path,
    types: &[OutputFormat],
) -> Vec<(OutputFormat, PathBuf)> {
    let mut seen = std::collections::HashSet::new();
    types
        .iter()
        .copied()
        .filter(|f| seen.insert(*f))
        .map(|fmt| {
            let mut path = output.to_path_buf();
            if path.extension().and_then(|e| e.to_str()) != Some(fmt.extension()) {
                path.set_extension(fmt.extension());
            }
            (fmt, path)
        })
        .collect()
}

/// The terminal output.
struct StdoutSink {
    writer: BufferWriter,
    no_color: bool,
    header_written: bool,
}

/// One output file.
struct FileSink<W> {
    path: PathBuf,
    writer: W,
}

fn write_error(path: &Path, e: &dyn std::fmt::Display) -> String {
    format!("Cannot write to output file {}: {e}", path.display())
}

/// The writers of one run. `stdout_profile` is used when no `-o` is given; `file_profile` for files.
///
/// Rows stream to the outputs as they are written, or, with `--sort`, are buffered and written in
/// time order by [`Writers::finish`]. The first I/O failure on a file is remembered and returned by
/// `finish()`; failures on the terminal (a closed pipe) are ignored like the sibling tools do.
#[derive(Default)]
pub struct Writers {
    pub paths: Vec<PathBuf>,
    /// The profile the rows are rendered with (its column names head the CSV and key the JSON).
    profile: Profile,
    stdout: Option<StdoutSink>,
    csv: Option<FileSink<csv::Writer<BufWriter<File>>>>,
    json: Option<FileSink<BufWriter<File>>>,
    jsonl: Option<FileSink<BufWriter<File>>>,
    /// `--sort`: the rows held back until `finish()`.
    pending: Option<Vec<Row>>,
    error: Option<String>,
}

impl Writers {
    /// A writer set with no outputs (every row is dropped).
    pub fn empty() -> Writers {
        Writers::default()
    }

    pub fn new(
        output: Option<&Path>,
        types: &[OutputFormat],
        stdout_profile: &Profile,
        file_profile: &Profile,
        no_color: bool,
        sort: bool,
    ) -> Result<Writers, String> {
        let mut writers = Writers {
            pending: sort.then(Vec::new),
            ..Writers::default()
        };
        let Some(base) = output else {
            writers.profile = stdout_profile.clone();
            let choice = if no_color {
                ColorChoice::Never
            } else {
                ColorChoice::Always
            };
            writers.stdout = Some(StdoutSink {
                writer: BufferWriter::stdout(choice),
                no_color,
                header_written: false,
            });
            return Ok(writers);
        };
        writers.profile = file_profile.clone();
        let types: &[OutputFormat] = if types.is_empty() {
            &[OutputFormat::Csv]
        } else {
            types
        };
        for (fmt, path) in resolve_output_targets(base, types) {
            let file = File::create(&path).map_err(|e| write_error(&path, &e))?;
            let buffered = BufWriter::new(file);
            match fmt {
                OutputFormat::Csv => {
                    let mut csv = csv::Writer::from_writer(buffered);
                    csv.write_record(writers.profile.column_names())
                        .map_err(|e| write_error(&path, &e))?;
                    writers.csv = Some(FileSink {
                        path: path.clone(),
                        writer: csv,
                    });
                }
                OutputFormat::Json => {
                    writers.json = Some(FileSink {
                        path: path.clone(),
                        writer: buffered,
                    });
                }
                OutputFormat::Jsonl => {
                    writers.jsonl = Some(FileSink {
                        path: path.clone(),
                        writer: buffered,
                    });
                }
            }
            writers.paths.push(path);
        }
        Ok(writers)
    }

    /// Whether rows go to the terminal.
    pub fn writes_stdout(&self) -> bool {
        self.paths.is_empty()
    }

    /// The profile rows must be rendered with.
    #[cfg(test)]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Write (or buffer, with `--sort`) one rendered row. `row` is rendered with the profile the
    /// writer set expects (stdout profile when writing to the terminal, file profile otherwise).
    pub fn write(&mut self, row: Row) {
        match &mut self.pending {
            Some(rows) => rows.push(row),
            None => self.emit(&row),
        }
    }

    fn emit(&mut self, row: &Row) {
        let mut failures: Vec<String> = Vec::new();
        if let Some(sink) = &mut self.stdout {
            let mut buf = sink.writer.buffer();
            let header = !sink.header_written;
            if render_stdout(&mut buf, &self.profile, row, header, sink.no_color).is_ok() {
                sink.header_written = true;
                // A closed pipe is not an error of the run.
                sink.writer.print(&buf).ok();
            }
        }
        if let Some(sink) = &mut self.csv {
            let record: Vec<String> = row_texts(&self.profile, row)
                .iter()
                .map(|t| sanitize_csv_field(t))
                .collect();
            if let Err(e) = sink.writer.write_record(&record) {
                failures.push(write_error(&sink.path, &e));
            }
        }
        if let Some(sink) = &mut self.json {
            let mut text = row_json(&self.profile, row, true);
            text.push('\n');
            if let Err(e) = sink.writer.write_all(text.as_bytes()) {
                failures.push(write_error(&sink.path, &e));
            }
        }
        if let Some(sink) = &mut self.jsonl {
            let mut text = row_json(&self.profile, row, false);
            text.push('\n');
            if let Err(e) = sink.writer.write_all(text.as_bytes()) {
                failures.push(write_error(&sink.path, &e));
            }
        }
        for failure in failures {
            self.note_error(failure);
        }
    }

    fn note_error(&mut self, msg: String) {
        if self.error.is_none() {
            self.error = Some(msg);
        }
    }

    /// Flush buffered rows (sorted) and close the files.
    pub fn finish(&mut self) -> Result<(), String> {
        if let Some(mut rows) = self.pending.take() {
            rows.sort_by(|a, b| compare_sort_keys(&a.sort_key, &b.sort_key));
            for row in &rows {
                self.emit(row);
            }
        }
        let mut failures: Vec<String> = Vec::new();
        if let Some(sink) = &mut self.csv
            && let Err(e) = sink.writer.flush()
        {
            failures.push(write_error(&sink.path, &e));
        }
        if let Some(sink) = &mut self.json
            && let Err(e) = sink.writer.flush()
        {
            failures.push(write_error(&sink.path, &e));
        }
        if let Some(sink) = &mut self.jsonl
            && let Err(e) = sink.writer.flush()
        {
            failures.push(write_error(&sink.path, &e));
        }
        for failure in failures {
            self.note_error(failure);
        }
        match self.error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ParsedEvent;
    use crate::logsource::LogSourceTag;
    use chrono::{FixedOffset, TimeZone};
    use std::sync::Arc;

    fn profiles() -> BTreeMap<String, Profile> {
        parse_profiles(DEFAULT_PROFILES).expect("default profiles parse")
    }

    fn verbose() -> Profile {
        profiles().remove("verbose").expect("verbose profile")
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).single().unwrap()
    }

    fn opts() -> RenderOptions {
        RenderOptions { utc: true }
    }

    /// An sshd line of `auth.log` at 2026-10-26 18:00:01 +09:00 (= 09:00:01 UTC).
    fn sshd_event() -> ParsedEvent {
        let mut ev = ParsedEvent::new(
            "Oct 26 18:00:01 webserver01 sshd[2001]: Invalid user admin from 198.51.100.23 port 40022",
            &LogSourceTag::LINUX_SYSLOG,
        );
        ev.timestamp = Some(
            FixedOffset::east_opt(9 * 3600)
                .unwrap()
                .with_ymd_and_hms(2026, 10, 26, 18, 0, 1)
                .single()
                .unwrap(),
        );
        ev.hostname = Some("webserver01".to_string());
        ev.add_tag(LogSourceTag::LINUX_AUTH);
        ev.set_primary(LogSourceTag::LINUX_SSHD);
        ev.push("process", "sshd");
        ev.push("pid", 2001i64);
        ev.push(
            "message",
            "Invalid user admin from 198.51.100.23 port 40022",
        );
        ev.push("facility", 4i64);
        ev.push("severity", FieldValue::Null);
        ev
    }

    fn meta() -> RuleMeta {
        RuleMeta {
            title: "Suspicious SSH Error".to_string(),
            id: Some("4d2a0e6c-1b5d-4c8c-9f0b-7f2a8b6c1d01".to_string()),
            level: "high".to_string(),
            status: Some("test".to_string()),
            author: Some("Yamato Security".to_string()),
            date: Some("2026/10/26".to_string()),
            modified: None,
            description: Some("Detects suspicious SSH error messages".to_string()),
            references: vec!["https://example.com/a".to_string()],
            tags: vec![
                "attack.initial-access".to_string(),
                "attack.t1190".to_string(),
                "cve.2026-109618".to_string(),
            ],
            falsepositives: vec!["Unknown".to_string()],
            rule_file: "lnx_sshd_susp_ssh.yml".to_string(),
        }
    }

    fn detection(event: ParsedEvent, line: usize) -> Detection {
        Detection {
            event,
            rule_index: 0,
            file: Arc::from("test_files/linux/auth.log"),
            line,
        }
    }

    fn names(profile: &Profile) -> Vec<&str> {
        profile.column_names()
    }

    // --- profiles -------------------------------------------------------------------------------

    #[test]
    fn default_profiles_parse_with_their_columns_in_order() {
        let profiles = profiles();
        assert_eq!(profiles.len(), 4);
        let mut keys: Vec<&str> = profiles.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["minimal", "standard", "super-verbose", "verbose"]
        );
        assert_eq!(
            names(&profiles["standard"]),
            vec![
                "Timestamp",
                "RuleTitle",
                "Level",
                "LogSource",
                "LogFile",
                "LineNumber",
                "Details"
            ]
        );
        let verbose = &profiles["verbose"];
        assert_eq!(verbose.name, "verbose");
        assert_eq!(verbose.columns.len(), 12);
        assert_eq!(&names(verbose)[9..], &["RuleFile", "RuleID", "LogFile"]);
        assert_eq!(
            verbose.columns[0],
            ("Timestamp".to_string(), Placeholder::Timestamp)
        );
        assert!(verbose.uses(Placeholder::Details));
        assert!(!verbose.uses(Placeholder::RawLine));
        assert_eq!(
            names(&profiles["minimal"]),
            vec!["Timestamp", "RuleTitle", "Level", "Details"]
        );
        assert_eq!(profiles["super-verbose"].columns.len(), 20);
        assert!(profiles["super-verbose"].uses(Placeholder::RawLine));
        // Linux logs have no computer column: a syslog host name stays available as %Computer%
        for profile in profiles.values() {
            assert!(!profile.uses(Placeholder::Computer), "{}", profile.name);
        }
    }

    #[test]
    fn custom_profile_keeps_non_alphabetical_column_order() {
        let yaml = "custom:\n    Zulu: \"%RuleTitle%\"\n    Alpha: \"%Timestamp%\"\n    Mike: \"%Level%\"\n";
        let profiles = parse_profiles(yaml).unwrap();
        assert_eq!(
            profiles["custom"].columns,
            vec![
                ("Zulu".to_string(), Placeholder::RuleTitle),
                ("Alpha".to_string(), Placeholder::Timestamp),
                ("Mike".to_string(), Placeholder::Level),
            ]
        );
    }

    #[test]
    fn unknown_placeholder_is_named_in_the_error() {
        let yaml = "standard:\n    Timestamp: \"%Timestamp%\"\n    Oops: \"%Bogus%\"\n";
        let err = parse_profiles(yaml).unwrap_err();
        assert!(err.contains("%Bogus%"), "{err}");
        assert!(err.contains("standard"), "{err}");
        assert!(err.contains("Oops"), "{err}");
    }

    #[test]
    fn malformed_profile_files_are_errors() {
        assert!(parse_profiles("").is_err(), "empty document");
        assert!(parse_profiles("- a\n- b\n").is_err(), "top-level list");
        let err = parse_profiles("standard: \"%Timestamp%\"\n").unwrap_err();
        assert!(err.contains("standard"), "{err}");
        let err = parse_profiles("standard:\n    Timestamp: [a, b]\n").unwrap_err();
        assert!(err.contains("Timestamp"), "{err}");
        let err = parse_profiles("standard: {}\n").unwrap_err();
        assert!(err.contains("no columns"), "{err}");
        assert!(
            parse_profiles("standard:\n  Timestamp: [\n").is_err(),
            "invalid YAML"
        );
        let err = parse_profiles("standard:\n    1: \"%Timestamp%\"\n").unwrap_err();
        assert!(err.contains("column names must be strings"), "{err}");
    }

    // --- rendering ----------------------------------------------------------------------------

    #[test]
    fn verbose_detection_renders_every_cell() {
        let row = render_detection(&detection(sshd_event(), 7), &meta(), &verbose(), &opts());
        assert_eq!(row.level, "high");
        assert_eq!(
            row.sort_key,
            (
                Some(utc(2026, 10, 26, 9, 0, 1)),
                "Suspicious SSH Error".to_string(),
                "test_files/linux/auth.log".to_string(),
                7
            )
        );
        assert_eq!(row.cells.len(), 12);
        assert_eq!(
            row.cells[0],
            Cell::Text("2026-10-26 09:00:01.000 +00:00".to_string())
        );
        assert_eq!(row.cells[1], Cell::Text("Suspicious SSH Error".to_string()));
        assert_eq!(row.cells[2], Cell::Text("high".to_string()));
        assert_eq!(row.cells[3], Cell::Text("linux/sshd".to_string()));
        assert_eq!(row.cells[4], Cell::List(vec!["InitAccess".to_string()]));
        assert_eq!(row.cells[5], Cell::List(vec!["T1190".to_string()]));
        assert_eq!(
            row.cells[6],
            Cell::List(vec!["cve.2026-109618".to_string()])
        );
        assert_eq!(row.cells[7], Cell::Number(7));
        // every parsed field, the main ones first
        assert_eq!(
            row.cells[8],
            Cell::Map(vec![
                ("Proc".to_string(), JsonValue::from("sshd")),
                ("PID".to_string(), JsonValue::from(2001)),
                (
                    "Msg".to_string(),
                    JsonValue::from("Invalid user admin from 198.51.100.23 port 40022")
                ),
                ("facility".to_string(), JsonValue::from(4)),
                ("severity".to_string(), JsonValue::Null),
            ])
        );
        assert_eq!(
            row.cells[9],
            Cell::Text("lnx_sshd_susp_ssh.yml".to_string())
        );
        assert_eq!(
            row.cells[10],
            Cell::Text("4d2a0e6c-1b5d-4c8c-9f0b-7f2a8b6c1d01".to_string())
        );
        assert_eq!(
            row.cells[11],
            Cell::Text("test_files/linux/auth.log".to_string())
        );
    }

    #[test]
    fn super_verbose_adds_rule_metadata_and_raw_line() {
        let profile = profiles().remove("super-verbose").unwrap();
        let mut m = meta();
        m.modified = Some("2026/10/27".to_string());
        let row = render_detection(&detection(sshd_event(), 1), &m, &profile, &opts());
        let cell = |name: &str| {
            let i = profile.columns.iter().position(|(c, _)| c == name).unwrap();
            row.cells[i].clone()
        };
        assert_eq!(
            cell("RawLine"),
            Cell::Text(
                "Oct 26 18:00:01 webserver01 sshd[2001]: Invalid user admin from 198.51.100.23 port 40022"
                    .to_string()
            )
        );
        assert_eq!(
            cell("RuleAuthor"),
            Cell::Text("Yamato Security".to_string())
        );
        assert_eq!(
            cell("RuleCreationDate"),
            Cell::Text("2026/10/26".to_string())
        );
        assert_eq!(
            cell("RuleModifiedDate"),
            Cell::Text("2026/10/27".to_string())
        );
        assert_eq!(cell("Status"), Cell::Text("test".to_string()));
        assert_eq!(
            cell("Description"),
            Cell::Text("Detects suspicious SSH error messages".to_string())
        );
        assert_eq!(
            cell("References"),
            Cell::List(vec!["https://example.com/a".to_string()])
        );
        assert_eq!(
            cell("FalsePositives"),
            Cell::List(vec!["Unknown".to_string()])
        );
    }

    #[test]
    fn missing_rule_metadata_renders_null() {
        let profile = profiles().remove("super-verbose").unwrap();
        let m = RuleMeta {
            title: "Bare".to_string(),
            level: "low".to_string(),
            ..RuleMeta::default()
        };
        let row = render_detection(&detection(sshd_event(), 1), &m, &profile, &opts());
        let cell = |name: &str| {
            let i = profile.columns.iter().position(|(c, _)| c == name).unwrap();
            row.cells[i].clone()
        };
        for name in [
            "RuleID",
            "RuleAuthor",
            "RuleCreationDate",
            "RuleModifiedDate",
            "Status",
            "Description",
            "RuleFile",
        ] {
            assert_eq!(cell(name), Cell::Null, "{name}");
        }
        assert_eq!(cell("References"), Cell::List(vec![]));
        assert_eq!(cell("MitreTactics"), Cell::List(vec![]));
        assert_eq!(cell_text(&cell("References")), "-");
        assert!(row_json(&profile, &row, false).contains("\"RuleID\":null"));
        assert!(row_json(&profile, &row, false).contains("\"References\":[]"));
    }

    #[test]
    fn details_flag_an_inferred_timestamp() {
        let profile = verbose();
        let mut ev = sshd_event();
        ev.timestamp_inferred = true;
        let row = render_detection(&detection(ev, 3), &meta(), &profile, &opts());
        let i = profile
            .columns
            .iter()
            .position(|(_, p)| *p == Placeholder::Details)
            .unwrap();
        assert_eq!(
            row.cells[i],
            Cell::Map(vec![
                ("Proc".to_string(), JsonValue::from("sshd")),
                ("PID".to_string(), JsonValue::from(2001)),
                (
                    "Msg".to_string(),
                    JsonValue::from("Invalid user admin from 198.51.100.23 port 40022")
                ),
                ("facility".to_string(), JsonValue::from(4)),
                ("severity".to_string(), JsonValue::Null),
                ("TimestampInferred".to_string(), JsonValue::Bool(true)),
            ])
        );
        assert_eq!(
            cell_text(&row.cells[i]),
            "Proc: sshd ¦ PID: 2001 ¦ Msg: Invalid user admin from 198.51.100.23 port 40022 ¦ facility: 4 ¦ severity: - ¦ TimestampInferred: true"
        );
        let plain = render_detection(&detection(sshd_event(), 3), &meta(), &profile, &opts());
        assert_eq!(
            cell_text(&plain.cells[i]),
            "Proc: sshd ¦ PID: 2001 ¦ Msg: Invalid user admin from 198.51.100.23 port 40022 ¦ facility: 4 ¦ severity: -"
        );
    }

    #[test]
    fn field_labels_follow_the_table_and_keep_other_keys() {
        for (key, label) in [
            ("process", "Proc"),
            ("pid", "PID"),
            ("message", "Msg"),
            ("c-ip", "SrcIP"),
            ("cs-method", "Method"),
            ("cs-uri-query", "URI"),
            ("sc-status", "Status"),
            ("sc-bytes", "Bytes"),
            ("cs-referer", "Referer"),
            ("cs-user-agent", "UA"),
            ("module", "Module"),
            ("level", "Level"),
            ("client", "Client"),
            ("php_type", "Type"),
            ("pool", "Pool"),
            ("child_pid", "ChildPID"),
            ("request", "Request"),
            ("upstream", "Upstream"),
            ("file", "PhpFile"),
            ("line", "PhpLine"),
            ("cs-uri-stem", "cs-uri-stem"),
            ("php_message", "php_message"),
            ("error_code", "error_code"),
        ] {
            assert_eq!(field_label(key), label, "{key}");
        }
    }

    #[test]
    fn access_log_details_keep_numbers_and_null_in_json() {
        let mut ev = ParsedEvent::new("raw", &LogSourceTag::WEBSERVER);
        ev.timestamp = Some(utc(2026, 10, 24, 15, 35, 38).fixed_offset());
        ev.push("c-ip", "162.35.99.94");
        ev.push("cs-method", "POST");
        ev.push("cs-uri-query", "/?q0000000=v&q0000001=v");
        ev.push("sc-status", 200i64);
        ev.push("sc-bytes", 0i64);
        ev.push("cs-referer", FieldValue::Null);
        ev.push("cs-user-agent", FieldValue::Null);
        ev.push("request_time", 0.512f64);
        ev.push("extra", true);
        let profile = profiles().remove("standard").unwrap();
        let row = render_detection(&detection(ev, 1), &meta(), &profile, &opts());
        assert_eq!(
            row.cells[0],
            Cell::Text("2026-10-24 15:35:38.000 +00:00".to_string())
        );
        assert_eq!(
            cell_text(&row.cells[6]),
            "SrcIP: 162.35.99.94 ¦ Method: POST ¦ URI: /?q0000000=v&q0000001=v ¦ Status: 200 ¦ Bytes: 0 ¦ Referer: - ¦ UA: - ¦ request_time: 0.512 ¦ extra: true"
        );
        let json = row_json(&profile, &row, false);
        assert!(
            json.contains("\"Status\":200,\"Bytes\":0,\"Referer\":null,\"UA\":null,\"request_time\":0.512,\"extra\":true"),
            "{json}"
        );
    }

    #[test]
    fn null_timestamp_renders_dash_in_text_and_null_in_json() {
        let mut ev = sshd_event();
        ev.timestamp = None;
        let row = render_detection(&detection(ev, 2), &meta(), &verbose(), &opts());
        assert_eq!(row.cells[0], Cell::Null);
        assert_eq!(row.sort_key.0, None);
        assert_eq!(cell_text(&row.cells[0]), "-");
        assert_eq!(row_texts(&verbose(), &row)[0], "-");
        let json = row_json(&verbose(), &row, false);
        assert!(json.starts_with("{\"Timestamp\":null,"), "{json}");
        let parsed: JsonValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Timestamp"], JsonValue::Null);
        assert_eq!(parsed["LineNumber"], JsonValue::from(2));
        assert_eq!(parsed["Details"]["PID"], JsonValue::from(2001));
        assert_eq!(parsed["MitreTags"], serde_json::json!(["T1190"]));
    }

    #[test]
    fn computer_is_the_hostname_in_a_custom_profile_and_null_without_one() {
        let profile = parse_profiles("custom:\n    Host: \"%Computer%\"\n")
            .unwrap()
            .remove("custom")
            .unwrap();
        let row = render_detection(&detection(sshd_event(), 1), &meta(), &profile, &opts());
        assert_eq!(row.cells[0], Cell::Text("webserver01".to_string()));
        let mut ev = sshd_event();
        ev.hostname = None;
        let row = render_detection(&detection(ev, 1), &meta(), &profile, &opts());
        assert_eq!(row.cells[0], Cell::Null);
        assert_eq!(row_texts(&profile, &row)[0], "-");
    }

    #[test]
    fn control_characters_are_escaped_everywhere() {
        let mut ev = sshd_event();
        ev.raw = "raw \u{1b}[31mred\u{1b}[0m".to_string();
        ev.hostname = Some("host\u{7}".to_string());
        ev.push("message", "sh: 1: wget\u{1b}]0;pwned\u{7}: not found");
        ev.push("x\u{1b}y", "value");
        let mut m = meta();
        m.title = "Title\u{9b}X".to_string();
        m.description = Some("desc\u{0}".to_string());
        m.references = vec!["ref\u{1b}".to_string()];
        m.tags.push("cve.\u{1b}2".to_string());
        let mut profile = profiles().remove("super-verbose").unwrap();
        profile
            .columns
            .push(("Computer".to_string(), Placeholder::Computer));
        let row = render_detection(&detection(ev, 1), &m, &profile, &opts());
        let text = row_texts(&profile, &row).join(" · ");
        assert!(!text.chars().any(|c| c.is_control() && c != '\t'), "{text}");
        assert!(text.contains("raw \\x1B[31mred\\x1B[0m"), "{text}");
        assert!(text.contains("host\\x07"), "{text}");
        assert!(
            text.contains("Msg: sh: 1: wget\\x1B]0;pwned\\x07: not found"),
            "{text}"
        );
        assert!(text.contains("x\\x1By: value"), "{text}");
        assert!(text.contains("Title\\x9BX"), "{text}");
        assert!(text.contains("desc\\x00"), "{text}");
        assert!(text.contains("ref\\x1B"), "{text}");
        assert!(text.contains("cve.\\x1B2"), "{text}");
        let json = row_json(&profile, &row, false);
        assert!(!json.chars().any(|c| c.is_control()), "{json}");
        assert!(json.contains("Title\\\\x9BX"), "{json}");
    }

    #[test]
    fn correlation_row_cells() {
        let hit = CorrelationHit {
            correlation_index: 0,
            timestamp: utc(2026, 10, 24, 15, 35, 44),
            first: utc(2026, 10, 24, 15, 35, 38),
            last: utc(2026, 10, 24, 15, 35, 44),
            count: 3,
            group_values: vec!["162.35.99.94".to_string()],
            members: vec![0, 1, 2],
            hostname: Some("honeypot".to_string()),
        };
        let member = |summary: &str, secs: u32| BaseHit {
            correlation_index: 0,
            base_index: 0,
            timestamp: utc(2026, 10, 24, 15, 35, secs),
            group_values: Some(vec!["162.35.99.94".to_string()]),
            value_field: None,
            hostname: Some("honeypot".to_string()),
            summary: summary.to_string(),
            file: std::sync::Arc::from("apache2/access.log"),
            line: 0,
        };
        let members = [
            member(
                "POST Request To Web Root Or PHP Index (apache2/access.log:3)",
                38,
            ),
            member(
                "PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure) (php-error.log:9)",
                40,
            ),
            member(
                "POST Request To Web Root Or PHP Index (apache2/access.log:4)",
                44,
            ),
        ];
        let refs: Vec<&BaseHit> = members.iter().collect();
        let m = RuleMeta {
            title: "Rapid Repeated POST Requests To PHP Index Page".to_string(),
            level: "medium".to_string(),
            tags: vec!["attack.initial-access".to_string()],
            rule_file: "web_rapid_posts_to_php_index.yml".to_string(),
            ..RuleMeta::default()
        };
        let profile = verbose();
        let row = render_correlation(&hit, &refs, &m, &profile, &opts());
        assert_eq!(row.level, "medium");
        assert_eq!(
            row.sort_key,
            (
                Some(utc(2026, 10, 24, 15, 35, 44)),
                "Rapid Repeated POST Requests To PHP Index Page".to_string(),
                String::new(),
                0
            )
        );
        let cell = |name: &str| {
            let i = profile.columns.iter().position(|(c, _)| c == name).unwrap();
            row.cells[i].clone()
        };
        assert_eq!(
            cell("Timestamp"),
            Cell::Text("2026-10-24 15:35:44.000 +00:00".to_string())
        );
        assert_eq!(cell("LogSource"), Cell::Text("correlation".to_string()));
        assert_eq!(cell("LineNumber"), Cell::Null);
        assert_eq!(
            cell("LogFile"),
            Cell::Text("apache2/access.log".to_string())
        );
        assert_eq!(
            cell("MitreTactics"),
            Cell::List(vec!["InitAccess".to_string()])
        );
        assert_eq!(
            cell("RuleFile"),
            Cell::Text("web_rapid_posts_to_php_index.yml".to_string())
        );
        let expected_details = vec![
            ("Count".to_string(), JsonValue::from(3)),
            (
                "Rules".to_string(),
                JsonValue::from(
                    "POST Request To Web Root Or PHP Index, PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure)",
                ),
            ),
            (
                "First".to_string(),
                JsonValue::from("2026-10-24 15:35:38.000 +00:00"),
            ),
            (
                "Last".to_string(),
                JsonValue::from("2026-10-24 15:35:44.000 +00:00"),
            ),
            ("GroupBy".to_string(), JsonValue::from("162.35.99.94")),
        ];
        let members = (
            "Members".to_string(),
            serde_json::json!([
                "POST Request To Web Root Or PHP Index (apache2/access.log:3)",
                "PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure) (php-error.log:9)",
                "POST Request To Web Root Or PHP Index (apache2/access.log:4)"
            ]),
        );
        let mut all = expected_details.clone();
        all.push(members.clone());
        assert_eq!(cell("Details"), Cell::Map(all));
        assert_eq!(
            cell_text(&cell("Details")),
            "Count: 3 ¦ Rules: POST Request To Web Root Or PHP Index, PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure) ¦ First: 2026-10-24 15:35:38.000 +00:00 ¦ Last: 2026-10-24 15:35:44.000 +00:00 ¦ GroupBy: 162.35.99.94 ¦ Members: POST Request To Web Root Or PHP Index (apache2/access.log:3), PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure) (php-error.log:9), POST Request To Web Root Or PHP Index (apache2/access.log:4)"
        );

        // Details / RawLine with the super-verbose profile, no group-by.
        let ungrouped = CorrelationHit {
            group_values: vec![],
            hostname: None,
            ..hit.clone()
        };
        let profile = profiles().remove("super-verbose").unwrap();
        let row = render_correlation(&ungrouped, &refs, &m, &profile, &opts());
        let cell = |name: &str| {
            let i = profile.columns.iter().position(|(c, _)| c == name).unwrap();
            row.cells[i].clone()
        };
        let mut ungrouped_details = expected_details[..4].to_vec();
        ungrouped_details.push(members);
        assert_eq!(
            cell("Details"),
            Cell::Map(ungrouped_details),
            "no GroupBy entry without group values"
        );
        assert_eq!(cell("RawLine"), Cell::Null);
    }

    #[test]
    fn member_titles_are_recovered_from_summaries() {
        assert_eq!(member_title("Title (file.log:12)"), "Title");
        assert_eq!(
            member_title("Title (With Parens) (dir/file.log:1)"),
            "Title (With Parens)"
        );
        assert_eq!(member_title("No location"), "No location");
        assert_eq!(member_title(" (x:1)"), " (x:1)");
        assert_eq!(member_title("Title (note)"), "Title (note)");
        assert_eq!(member_title("Title (x:)"), "Title (x:)");
        assert_eq!(member_title("Title (C:\\logs\\a.log:7)"), "Title");
    }

    // --- timestamps -----------------------------------------------------------------------------

    #[test]
    fn timestamps_format_in_utc_and_local_time() {
        let t = utc(2026, 10, 24, 15, 35, 38) + chrono::Duration::milliseconds(673);
        assert_eq!(format_timestamp(&t, true), "2026-10-24 15:35:38.673 +00:00");
        let local = format_timestamp(&t, false);
        let back = DateTime::parse_from_str(&local, "%Y-%m-%d %H:%M:%S%.3f %:z").unwrap();
        assert_eq!(back.with_timezone(&Utc), t);
        assert_eq!(local.len(), "2026-10-24 15:35:38.673 +00:00".len());
    }

    // --- text and JSON rendering -------------------------------------------------------------------

    #[test]
    fn cell_text_shapes() {
        assert_eq!(cell_text(&Cell::Null), "-");
        assert_eq!(cell_text(&Cell::Number(-12)), "-12");
        assert_eq!(cell_text(&Cell::Text("x".into())), "x");
        assert_eq!(cell_text(&Cell::Map(vec![])), "-");
        assert_eq!(cell_text(&Cell::List(vec![])), "-");
        assert_eq!(
            cell_text(&Cell::List(vec!["a".into(), "b".into()])),
            "a ¦ b"
        );
        assert_eq!(
            cell_text(&Cell::Map(vec![
                ("A".into(), JsonValue::from("x")),
                ("B".into(), JsonValue::from(1)),
                ("C".into(), JsonValue::Null),
                ("D".into(), JsonValue::Bool(false)),
                ("E".into(), serde_json::json!(["p", "q"])),
                ("F".into(), serde_json::json!(1.5)),
            ])),
            "A: x ¦ B: 1 ¦ C: - ¦ D: false ¦ E: p, q ¦ F: 1.5"
        );
    }

    #[test]
    fn pretty_json_matches_serde_layout_and_keeps_order() {
        let profile = Profile {
            name: "t".into(),
            columns: vec![
                ("Timestamp".into(), Placeholder::Timestamp),
                ("Details".into(), Placeholder::Details),
                ("MitreTags".into(), Placeholder::MitreTags),
                ("LineNumber".into(), Placeholder::LineNumber),
                ("RuleID".into(), Placeholder::RuleID),
                ("Empty".into(), Placeholder::Details),
                ("NoTags".into(), Placeholder::OtherTags),
            ],
        };
        let row = Row {
            sort_key: (None, String::new(), String::new(), 0),
            level: "low".into(),
            cells: vec![
                Cell::Text("2026-10-24 15:35:38.673 +00:00".into()),
                Cell::Map(vec![
                    ("Proc".into(), JsonValue::from("sshd")),
                    ("PID".into(), JsonValue::from(2001)),
                    ("Nested".into(), serde_json::json!({"b": [1, 2], "a": null})),
                ]),
                Cell::List(vec!["T1190".into(), "T1053.003".into()]),
                Cell::Number(7),
                Cell::Null,
                Cell::Map(vec![]),
                Cell::List(vec![]),
            ],
        };
        let pretty = row_json(&profile, &row, true);
        let compact = row_json(&profile, &row, false);
        // Both forms parse to the same tree, and that tree matches serde_json's own layout.
        let tree: JsonValue = serde_json::from_str(&pretty).unwrap();
        assert_eq!(tree, serde_json::from_str::<JsonValue>(&compact).unwrap());
        // serde_json sorts object keys (BTreeMap), so compare on a key-sorted projection: nested
        // containers must be laid out exactly like serde_json's pretty printer.
        let nested = &tree["Details"]["Nested"];
        let serde_pretty = serde_json::to_string_pretty(nested).unwrap();
        let ours = {
            let mut out = String::new();
            write_json_node(&mut out, &json_node_of_value(nested), 0, true);
            out
        };
        assert_eq!(ours, serde_pretty);
        assert_eq!(
            pretty,
            "{\n  \"Timestamp\": \"2026-10-24 15:35:38.673 +00:00\",\n  \"Details\": {\n    \"Proc\": \"sshd\",\n    \"PID\": 2001,\n    \"Nested\": {\n      \"a\": null,\n      \"b\": [\n        1,\n        2\n      ]\n    }\n  },\n  \"MitreTags\": [\n    \"T1190\",\n    \"T1053.003\"\n  ],\n  \"LineNumber\": 7,\n  \"RuleID\": null,\n  \"Empty\": {},\n  \"NoTags\": []\n}"
        );
        assert_eq!(
            compact,
            "{\"Timestamp\":\"2026-10-24 15:35:38.673 +00:00\",\"Details\":{\"Proc\":\"sshd\",\"PID\":2001,\"Nested\":{\"a\":null,\"b\":[1,2]}},\"MitreTags\":[\"T1190\",\"T1053.003\"],\"LineNumber\":7,\"RuleID\":null,\"Empty\":{},\"NoTags\":[]}"
        );
        // Column order is the profile order even when it is not alphabetical.
        let t = compact.find("\"Timestamp\"").unwrap();
        let d = compact.find("\"Details\"").unwrap();
        let l = compact.find("\"LineNumber\"").unwrap();
        assert!(t < d && d < l);
    }

    #[test]
    fn json_strings_are_escaped() {
        let profile = Profile {
            name: "t".into(),
            columns: vec![("RawLine".into(), Placeholder::RawLine)],
        };
        let row = Row {
            sort_key: (None, String::new(), String::new(), 0),
            level: "low".into(),
            cells: vec![Cell::Text("quote \" backslash \\ tab\t日本".into())],
        };
        let json = row_json(&profile, &row, false);
        assert_eq!(
            json,
            "{\"RawLine\":\"quote \\\" backslash \\\\ tab\\t日本\"}"
        );
        let tree: JsonValue = serde_json::from_str(&json).unwrap();
        assert_eq!(tree["RawLine"], "quote \" backslash \\ tab\t日本");
    }

    #[test]
    fn short_rows_are_padded_with_null() {
        let profile = profiles().remove("minimal").unwrap();
        let row = Row {
            sort_key: (None, String::new(), String::new(), 0),
            level: "low".into(),
            cells: vec![Cell::Text("t".into())],
        };
        assert_eq!(row_texts(&profile, &row), vec!["t", "-", "-", "-"]);
        assert_eq!(
            row_json(&profile, &row, false),
            "{\"Timestamp\":\"t\",\"RuleTitle\":null,\"Level\":null,\"Details\":null}"
        );
    }

    #[test]
    fn stdout_rendering_has_header_separator_and_level_color() {
        let profile = profiles().remove("standard").unwrap();
        let mut m = meta();
        m.level = "critical".to_string();
        let row = render_detection(&detection(sshd_event(), 1), &m, &profile, &opts());
        let mut plain = Buffer::no_color();
        render_stdout(&mut plain, &profile, &row, true, true).unwrap();
        let text = String::from_utf8(plain.into_inner()).unwrap();
        assert_eq!(
            text,
            "Timestamp · RuleTitle · Level · LogSource · LogFile · LineNumber · Details\n\n2026-10-26 09:00:01.000 +00:00 · Suspicious SSH Error · critical · linux/sshd · test_files/linux/auth.log · 1 · Proc: sshd ¦ PID: 2001 ¦ Msg: Invalid user admin from 198.51.100.23 port 40022 ¦ facility: 4 ¦ severity: -\n\n"
        );
        let mut colored = Buffer::ansi();
        render_stdout(&mut colored, &profile, &row, false, false).unwrap();
        let text = String::from_utf8(colored.into_inner()).unwrap();
        assert!(!text.starts_with("Timestamp"), "no header on later rows");
        assert!(
            text.contains("\u{1b}[38;2;255;0;0m2026-10-26 09:00:01.000 +00:00 · Suspicious SSH Error · critical"),
            "{text:?}"
        );
        // high is orange, informational carries no color.
        for (level, color) in [
            ("high", Some("\u{1b}[38;2;255;175;0m")),
            ("medium", Some("\u{1b}[38;2;255;255;0m")),
            ("low", Some("\u{1b}[38;2;0;255;0m")),
            ("informational", None),
        ] {
            let mut m = meta();
            m.level = level.to_string();
            let row = render_detection(&detection(sshd_event(), 1), &m, &profile, &opts());
            let mut buf = Buffer::ansi();
            render_stdout(&mut buf, &profile, &row, false, false).unwrap();
            let text = String::from_utf8(buf.into_inner()).unwrap();
            match color {
                Some(c) => assert!(text.contains(c), "{level}: {text:?}"),
                None => assert!(!text.contains("\u{1b}[38;2"), "{level}: {text:?}"),
            }
            assert!(
                text.contains(&format!(" · {level} · ")),
                "{level}: {text:?}"
            );
        }
    }

    // --- writers ---------------------------------------------------------------------------------

    #[test]
    fn output_targets_get_one_extension_per_type() {
        let targets = resolve_output_targets(
            Path::new("timeline"),
            &[OutputFormat::Csv, OutputFormat::Jsonl],
        );
        assert_eq!(
            targets,
            vec![
                (OutputFormat::Csv, PathBuf::from("timeline.csv")),
                (OutputFormat::Jsonl, PathBuf::from("timeline.jsonl")),
            ]
        );
        assert_eq!(
            resolve_output_targets(Path::new("out.csv"), &[OutputFormat::Csv]),
            vec![(OutputFormat::Csv, PathBuf::from("out.csv"))]
        );
        assert_eq!(
            resolve_output_targets(
                Path::new("out.csv"),
                &[OutputFormat::Json, OutputFormat::Json, OutputFormat::Csv]
            ),
            vec![
                (OutputFormat::Json, PathBuf::from("out.json")),
                (OutputFormat::Csv, PathBuf::from("out.csv")),
            ]
        );
        assert_eq!(
            resolve_output_targets(Path::new("dir/report.2026"), &[OutputFormat::Jsonl]),
            vec![(OutputFormat::Jsonl, PathBuf::from("dir/report.jsonl"))]
        );
    }

    fn two_rows() -> (Row, Row) {
        let first = render_detection(&detection(sshd_event(), 1), &meta(), &verbose(), &opts());
        let mut ev = sshd_event();
        ev.timestamp = None;
        ev.hostname = None;
        ev.push("message", "=cmd|' /C calc'!A0");
        let mut m = meta();
        m.title = "Formula Title".to_string();
        m.level = "critical".to_string();
        m.id = None;
        let second = render_detection(&detection(ev, 2), &m, &verbose(), &opts());
        (first, second)
    }

    #[test]
    fn writers_produce_csv_json_and_jsonl_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("timeline");
        let standard = profiles().remove("standard").unwrap();
        let mut writers = Writers::new(
            Some(&base),
            &[OutputFormat::Csv, OutputFormat::Json, OutputFormat::Jsonl],
            &standard,
            &verbose(),
            true,
            false,
        )
        .unwrap();
        assert!(!writers.writes_stdout());
        assert_eq!(writers.profile().name, "verbose");
        assert_eq!(
            writers.paths,
            vec![
                dir.path().join("timeline.csv"),
                dir.path().join("timeline.json"),
                dir.path().join("timeline.jsonl"),
            ]
        );
        let (first, second) = two_rows();
        writers.write(first);
        writers.write(second);
        writers.finish().unwrap();

        // CSV: header + 2 rows, structured cells flattened, CSV-only sanitization applied.
        let csv_text = std::fs::read_to_string(dir.path().join("timeline.csv")).unwrap();
        let mut rdr = csv::Reader::from_reader(csv_text.as_bytes());
        let header: Vec<String> = rdr
            .headers()
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(header, names(&verbose()));
        let records: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(&records[0][0], "2026-10-26 09:00:01.000 +00:00");
        assert_eq!(&records[0][1], "Suspicious SSH Error");
        assert_eq!(&records[0][2], "high");
        assert_eq!(&records[0][3], "linux/sshd");
        assert_eq!(&records[0][4], "InitAccess");
        assert_eq!(&records[0][5], "T1190");
        assert_eq!(&records[0][7], "1");
        assert_eq!(
            &records[0][8],
            "Proc: sshd ¦ PID: 2001 ¦ Msg: Invalid user admin from 198.51.100.23 port 40022 ¦ facility: 4 ¦ severity: -"
        );
        assert_eq!(&records[0][11], "test_files/linux/auth.log");
        // The second row: no timestamp (the bare `-` placeholder is kept readable: a whole-cell `-`
        // is plain text to spreadsheets), a formula in the message gets the apostrophe, no rule id.
        assert_eq!(&records[1][0], "-");
        assert_eq!(&records[1][2], "critical");
        assert_eq!(&records[1][7], "2");
        assert!(
            records[1][8].starts_with("Proc: sshd"),
            "the cell starts with the label, not the formula"
        );
        assert_eq!(&records[1][10], "-");
        // A cell whose text itself starts with a formula character is neutralized.
        let mut formula_profile = verbose();
        formula_profile.columns = vec![("RawLine".to_string(), Placeholder::RawLine)];
        let formula_dir = tempfile::tempdir().unwrap();
        let mut w = Writers::new(
            Some(&formula_dir.path().join("f.csv")),
            &[OutputFormat::Csv],
            &formula_profile,
            &formula_profile,
            true,
            false,
        )
        .unwrap();
        let mut ev = sshd_event();
        ev.raw = "=cmd|' /C calc'!A0".to_string();
        w.write(render_detection(
            &detection(ev, 1),
            &meta(),
            &formula_profile,
            &opts(),
        ));
        w.finish().unwrap();
        let text = std::fs::read_to_string(formula_dir.path().join("f.csv")).unwrap();
        assert_eq!(text, "RawLine\n'=cmd|' /C calc'!A0\n");

        // JSON: newline-separated pretty objects (not an array), keys in profile order.
        let json_text = std::fs::read_to_string(dir.path().join("timeline.json")).unwrap();
        assert!(json_text.starts_with("{\n  \"Timestamp\": \"2026-10-26 09:00:01.000 +00:00\",\n"));
        assert!(
            json_text.contains("\n}\n{\n"),
            "objects are separated by a newline"
        );
        let objects: Vec<JsonValue> = serde_json::Deserializer::from_str(&json_text)
            .into_iter::<JsonValue>()
            .map(|v| v.unwrap())
            .collect();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0]["RuleTitle"], "Suspicious SSH Error");
        assert_eq!(objects[0]["LineNumber"], 1);
        assert_eq!(objects[0]["Details"]["PID"], 2001);
        assert_eq!(objects[0]["Details"]["severity"], JsonValue::Null);
        assert_eq!(
            objects[0]["MitreTactics"],
            serde_json::json!(["InitAccess"])
        );
        assert_eq!(objects[1]["Timestamp"], JsonValue::Null);
        assert!(objects[1].get("Computer").is_none());
        assert_eq!(objects[1]["RuleID"], JsonValue::Null);
        assert_eq!(objects[1]["Details"]["Msg"], "=cmd|' /C calc'!A0");

        // JSONL: one compact object per line.
        let jsonl_text = std::fs::read_to_string(dir.path().join("timeline.jsonl")).unwrap();
        let lines: Vec<&str> = jsonl_text.lines().collect();
        assert_eq!(lines.len(), 2);
        for (line, object) in lines.iter().zip(&objects) {
            assert!(!line.contains('\n'));
            assert!(line.starts_with("{\"Timestamp\":"));
            assert_eq!(&serde_json::from_str::<JsonValue>(line).unwrap(), object);
        }
    }

    #[test]
    fn csv_only_is_the_default_type_and_single_type_keeps_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.csv");
        let p = profiles().remove("minimal").unwrap();
        let mut writers = Writers::new(Some(&out), &[], &p, &p, true, false).unwrap();
        assert_eq!(writers.paths, vec![out.clone()]);
        writers.finish().unwrap();
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "Timestamp,RuleTitle,Level,Details\n"
        );
    }

    #[test]
    fn sort_orders_rows_by_time_with_unknown_times_last() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("sorted.jsonl");
        let p = profiles().remove("standard").unwrap();
        let mut writers =
            Writers::new(Some(&out), &[OutputFormat::Jsonl], &p, &p, true, true).unwrap();
        let at = |secs: Option<u32>, title: &str, line: usize| {
            let mut ev = sshd_event();
            ev.timestamp = secs.map(|s| utc(2026, 10, 26, 9, 0, s).fixed_offset());
            let mut m = meta();
            m.title = title.to_string();
            render_detection(&detection(ev, line), &m, &p, &opts())
        };
        writers.write(at(Some(5), "B", 1));
        writers.write(at(None, "Z", 2));
        writers.write(at(Some(1), "C", 3));
        writers.write(at(Some(5), "A", 4));
        writers.write(at(None, "Y", 5));
        writers.write(at(Some(5), "A", 0));
        // Nothing is on disk before finish().
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "");
        writers.finish().unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let titles: Vec<String> = text
            .lines()
            .map(|l| {
                serde_json::from_str::<JsonValue>(l).unwrap()["RuleTitle"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        // time, then title, then file/line; unknown times last in title order.
        assert_eq!(titles, vec!["C", "A", "A", "B", "Y", "Z"]);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[1].contains("\"Timestamp\":\"2026-10-26 09:00:05.000 +00:00\""));
        assert!(lines[4].contains("\"Timestamp\":null"));
    }

    #[test]
    fn without_sort_rows_keep_arrival_order() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("plain.jsonl");
        let p = profiles().remove("minimal").unwrap();
        let mut writers =
            Writers::new(Some(&out), &[OutputFormat::Jsonl], &p, &p, true, false).unwrap();
        for (secs, title) in [(5u32, "late"), (1, "early")] {
            let mut ev = sshd_event();
            ev.timestamp = Some(utc(2026, 10, 26, 9, 0, secs).fixed_offset());
            let mut m = meta();
            m.title = title.to_string();
            writers.write(render_detection(&detection(ev, 1), &m, &p, &opts()));
        }
        writers.finish().unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].contains("\"late\""));
        assert!(lines[1].contains("\"early\""));
    }

    #[test]
    fn sort_key_comparison() {
        let t1 = utc(2026, 1, 1, 0, 0, 1);
        let t2 = utc(2026, 1, 1, 0, 0, 2);
        let k = |t: Option<DateTime<Utc>>, title: &str, file: &str, line: usize| {
            (t, title.to_string(), file.to_string(), line)
        };
        assert_eq!(
            compare_sort_keys(&k(Some(t1), "b", "f", 1), &k(Some(t2), "a", "f", 1)),
            Ordering::Less
        );
        assert_eq!(
            compare_sort_keys(&k(None, "a", "f", 1), &k(Some(t2), "z", "f", 1)),
            Ordering::Greater
        );
        assert_eq!(
            compare_sort_keys(&k(None, "a", "f", 1), &k(None, "b", "f", 1)),
            Ordering::Less
        );
        assert_eq!(
            compare_sort_keys(&k(Some(t1), "a", "f", 2), &k(Some(t1), "a", "f", 1)),
            Ordering::Greater
        );
        assert_eq!(
            compare_sort_keys(&k(Some(t1), "a", "a.log", 9), &k(Some(t1), "a", "b.log", 1)),
            Ordering::Less
        );
        assert_eq!(
            compare_sort_keys(&k(Some(t1), "a", "f", 1), &k(Some(t1), "a", "f", 1)),
            Ordering::Equal
        );
    }

    #[test]
    fn stdout_writer_has_no_paths_and_uses_the_stdout_profile() {
        let standard = profiles().remove("standard").unwrap();
        let writers = Writers::new(
            None,
            &[OutputFormat::Csv],
            &standard,
            &verbose(),
            true,
            false,
        )
        .unwrap();
        assert!(writers.writes_stdout());
        assert!(writers.paths.is_empty());
        assert_eq!(writers.profile().name, "standard");
        assert!(Writers::empty().writes_stdout());
        let mut empty = Writers::empty();
        empty.write(two_rows().0);
        assert!(empty.finish().is_ok());
    }

    #[test]
    fn unwritable_output_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-dir").join("out");
        let p = profiles().remove("minimal").unwrap();
        let Err(err) = Writers::new(Some(&missing), &[OutputFormat::Csv], &p, &p, true, false)
        else {
            panic!("creating the output in a missing directory must fail");
        };
        assert!(err.starts_with("Cannot write to output file"), "{err}");
        assert!(err.contains("out.csv"), "{err}");
    }

    #[test]
    fn existing_file_is_overwritten_by_new() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("x.jsonl");
        std::fs::write(&out, "stale\n").unwrap();
        let p = profiles().remove("minimal").unwrap();
        let mut writers =
            Writers::new(Some(&out), &[OutputFormat::Jsonl], &p, &p, true, false).unwrap();
        writers.finish().unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "");
    }
}
