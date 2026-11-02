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

//! The parsed event model shared by every parser, the detection engine and the output.

use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};
use serde_json::Value as JsonValue;
use sigma_rust::Event;

/// A parsed field value. Numbers are always `i64`: sigma-rust compares `Int` and `Unsigned` as
/// unequal, and YAML numbers in rules deserialize as `Int`. `Null` is a *present* field with no
/// value (CLF `-`), which is what a Sigma `field: null` test needs.
#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    Str(String),
    Int(i64),
    /// Only for values that are not integers (JSON `request_time: 0.512`); never used for the
    /// taxonomy's numeric fields.
    Float(f64),
    Bool(bool),
    Null,
}

impl FieldValue {
    /// Text for the terminal and CSV (`-` for `Null`).
    pub fn render(&self) -> String {
        match self {
            FieldValue::Str(s) => s.clone(),
            FieldValue::Int(i) => i.to_string(),
            FieldValue::Float(f) => f.to_string(),
            FieldValue::Bool(b) => b.to_string(),
            FieldValue::Null => "-".to_string(),
        }
    }

    /// JSON representation (`null` for `Null`).
    pub fn to_json(&self) -> JsonValue {
        match self {
            FieldValue::Str(s) => JsonValue::String(s.clone()),
            FieldValue::Int(i) => JsonValue::from(*i),
            FieldValue::Float(f) => serde_json::Number::from_f64(*f)
                .map(JsonValue::Number)
                .unwrap_or(JsonValue::Null),
            FieldValue::Bool(b) => JsonValue::Bool(*b),
            FieldValue::Null => JsonValue::Null,
        }
    }

    /// A string that is `-` or empty becomes `Null`, anything else `Str`.
    pub fn str_or_null(s: &str) -> FieldValue {
        if s.is_empty() || s == "-" {
            FieldValue::Null
        } else {
            FieldValue::Str(s.to_string())
        }
    }

    /// An integer, or `Null` when the text is `-`/empty/not a number.
    pub fn int_or_null(s: &str) -> FieldValue {
        s.trim()
            .parse::<i64>()
            .map(FieldValue::Int)
            .unwrap_or(FieldValue::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Insert this value into a sigma-rust event under `key`.
    pub fn insert_into(&self, event: &mut Event, key: &str) {
        match self {
            FieldValue::Str(s) => event.insert(key, s.as_str()),
            FieldValue::Int(i) => event.insert(key, *i),
            FieldValue::Float(f) => event.insert(key, *f),
            FieldValue::Bool(b) => event.insert(key, *b),
            FieldValue::Null => event.insert(key, None),
        }
    }
}

impl From<&str> for FieldValue {
    fn from(s: &str) -> Self {
        FieldValue::Str(s.to_string())
    }
}

impl From<String> for FieldValue {
    fn from(s: String) -> Self {
        FieldValue::Str(s)
    }
}

impl From<i64> for FieldValue {
    fn from(i: i64) -> Self {
        FieldValue::Int(i)
    }
}

impl From<f64> for FieldValue {
    fn from(f: f64) -> Self {
        FieldValue::Float(f)
    }
}

impl From<bool> for FieldValue {
    fn from(b: bool) -> Self {
        FieldValue::Bool(b)
    }
}

impl<T: Into<FieldValue>> From<Option<T>> for FieldValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => v.into(),
            None => FieldValue::Null,
        }
    }
}

/// One parsed log line.
#[derive(Clone, Debug)]
pub struct ParsedEvent {
    /// The event time as written in the log (with the assumed zone when the log had none).
    pub timestamp: Option<DateTime<FixedOffset>>,
    /// True when the line had no timestamp of its own and borrowed the previous entry's.
    pub timestamp_inferred: bool,
    /// True when the line's timestamp carried its own timezone (so `-z` was not needed for it).
    pub tz_explicit: bool,
    /// Host name from the line (syslog) or the hostname hint (live analysis).
    pub hostname: Option<String>,
    /// Shown in the `LogSource` column, e.g. `linux/sshd`, `webserver`, `apache`, `php/error_log`.
    pub primary_logsource: String,
    /// Every log source identity of this event.
    pub tags: Vec<LogSourceTag>,
    /// Parsed fields in display order (the `Details` column): the main fields of the format first.
    pub fields: Vec<(String, FieldValue)>,
    /// The original line, without the trailing newline.
    pub raw: String,
    /// The text keyword lists are matched against when it differs from `raw`: an audit record
    /// whose hex-encoded values were decoded matches `grep` / `password` keywords the way
    /// `ausearch -i` shows it. Never shown in the output.
    pub match_text: Option<String>,
}

impl ParsedEvent {
    pub fn new(raw: &str, primary: &LogSourceTag) -> Self {
        Self {
            timestamp: None,
            timestamp_inferred: false,
            tz_explicit: false,
            hostname: None,
            primary_logsource: primary.display(),
            tags: vec![*primary],
            fields: Vec::new(),
            raw: raw.to_string(),
            match_text: None,
        }
    }

    /// Append a field (keeps insertion order; a repeated key replaces the earlier value in place).
    pub fn push(&mut self, key: &str, value: impl Into<FieldValue>) {
        let value = value.into();
        if let Some(existing) = self.fields.iter_mut().find(|(k, _)| k == key) {
            existing.1 = value;
        } else {
            self.fields.push((key.to_string(), value));
        }
    }

    pub fn add_tag(&mut self, tag: LogSourceTag) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    pub fn add_tags(&mut self, tags: &[LogSourceTag]) {
        for t in tags {
            self.add_tag(*t);
        }
    }

    /// Make `tag` the one shown in the `LogSource` column (and part of the tag set).
    pub fn set_primary(&mut self, tag: LogSourceTag) {
        self.add_tag(tag);
        self.primary_logsource = tag.display();
    }

    #[cfg(test)]
    pub fn field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    #[cfg(test)]
    pub fn field_str(&self, key: &str) -> Option<&str> {
        self.field(key).and_then(FieldValue::as_str)
    }

    /// The sigma-rust event: every field, plus `hostname` and `raw` (the whole line, so that
    /// keywords match "the full log message" as the Sigma specification requires; for an audit
    /// record with decoded values, the line followed by the decoded values).
    pub fn to_sigma_event(&self) -> Event {
        let mut event = Event::new();
        for (k, v) in &self.fields {
            v.insert_into(&mut event, k);
        }
        if let Some(h) = &self.hostname {
            event.insert("hostname", h.as_str());
        }
        event.insert("raw", self.match_text.as_deref().unwrap_or(&self.raw));
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_numbers_round_trip_into_sigma_events() {
        let mut ev = ParsedEvent::new("raw line", &LogSourceTag::WEBSERVER);
        ev.push("cs-method", "POST");
        ev.push("sc-status", 404i64);
        ev.push("cs-referer", FieldValue::str_or_null("-"));
        ev.push("sc-bytes", FieldValue::int_or_null("-"));
        ev.push("extra", true);
        ev.hostname = Some("web01".into());
        assert_eq!(ev.fields.len(), 5);
        let rule = sigma_rust::rule_from_yaml(
            "title: t\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-method: POST\n    cs-referer: null\n    sc-status|gte: 400\n    hostname: web01\n  condition: sel\n",
        )
        .unwrap();
        assert!(rule.is_match(&ev.to_sigma_event()));
        let miss = sigma_rust::rule_from_yaml(
            "title: t\nlogsource: {category: webserver}\ndetection:\n  sel:\n    sc-bytes: null\n  condition: sel\n",
        )
        .unwrap();
        assert!(
            miss.is_match(&ev.to_sigma_event()),
            "int_or_null('-') must be Null"
        );
    }

    #[test]
    fn push_replaces_existing_key() {
        let mut ev = ParsedEvent::new("x", &LogSourceTag::LINUX_SYSLOG);
        ev.push("a", 1i64);
        ev.push("a", 2i64);
        assert_eq!(ev.fields.len(), 1);
        assert_eq!(ev.field("a"), Some(&FieldValue::Int(2)));
    }

    #[test]
    fn tags_are_deduplicated_and_primary_is_tracked() {
        let mut ev = ParsedEvent::new("x", &LogSourceTag::LINUX_SYSLOG);
        ev.add_tag(LogSourceTag::LINUX_SYSLOG);
        ev.set_primary(LogSourceTag::LINUX_SSHD);
        assert_eq!(
            ev.tags,
            vec![LogSourceTag::LINUX_SYSLOG, LogSourceTag::LINUX_SSHD]
        );
        assert_eq!(ev.primary_logsource, "linux/sshd");
    }
}
