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

//! Results summary (design §9), printed after the rows unless `-N`.
//!
//! The layout follows Suzaku and Hayabusa: the hit/event counts with the data reduction, the
//! `Total | Unique` detections per level, the first/last event time, the busiest date per level,
//! the `Top <level> alerts` tables (two levels per table row), the rule authors table, and,
//! iwatobi's own, the scanned/skipped file counts and the correlation hits dropped for a missing
//! `group-by` field. Every line honors `-K, --no-color`.

use crate::color::IwatobiColor;
use crate::output::format_timestamp;
use crate::util::{fmt_num, sanitize_control_chars};
use chrono::{DateTime, Utc};
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table, TableStyle};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

/// The Sigma levels in the order the summary lists them.
pub const LEVELS: [&str; 5] = ["critical", "high", "medium", "low", "informational"];
/// Rules shown per level in the `Top <level> alerts` tables.
const TOP_ALERTS: usize = 5;
/// Longest author name shown as is in the authors table; longer names are cut to
/// `AUTHOR_NAME_KEEP_CHARS` plus `...`, like the sibling tools.
const AUTHOR_NAME_MAX_CHARS: usize = 27;
const AUTHOR_NAME_KEEP_CHARS: usize = 24;
/// Terminal width assumed when it cannot be measured (not a terminal).
const DEFAULT_TERMINAL_WIDTH: usize = 100;

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub total_events: usize,
    pub events_with_hits: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// level → rule title → detections
    pub level_counts: BTreeMap<String, BTreeMap<String, usize>>,
    /// level → date (output timezone) → detections
    pub date_counts: BTreeMap<String, BTreeMap<String, usize>>,
    /// author → titles
    pub authors: BTreeMap<String, BTreeSet<String>>,
    pub first_event: Option<DateTime<Utc>>,
    pub last_event: Option<DateTime<Utc>>,
    /// format name → files
    pub formats: BTreeMap<String, usize>,
    pub correlation_hits_skipped: usize,
}

impl Summary {
    /// Record one detection.
    pub fn record(&mut self, level: &str, title: &str, author: Option<&str>, date: Option<&str>) {
        *self
            .level_counts
            .entry(level.to_string())
            .or_default()
            .entry(title.to_string())
            .or_default() += 1;
        if let Some(d) = date {
            *self
                .date_counts
                .entry(level.to_string())
                .or_default()
                .entry(d.to_string())
                .or_default() += 1;
        }
        if let Some(a) = author {
            self.authors
                .entry(a.to_string())
                .or_default()
                .insert(title.to_string());
        }
    }

    /// Track the first/last event time seen.
    pub fn see_time(&mut self, t: DateTime<Utc>) {
        if self.first_event.is_none_or(|f| t < f) {
            self.first_event = Some(t);
        }
        if self.last_event.is_none_or(|l| t > l) {
            self.last_event = Some(t);
        }
    }

    pub fn merge(&mut self, other: Summary) {
        self.total_events += other.total_events;
        self.events_with_hits += other.events_with_hits;
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        for (level, titles) in other.level_counts {
            let e = self.level_counts.entry(level).or_default();
            for (t, n) in titles {
                *e.entry(t).or_default() += n;
            }
        }
        for (level, dates) in other.date_counts {
            let e = self.date_counts.entry(level).or_default();
            for (d, n) in dates {
                *e.entry(d).or_default() += n;
            }
        }
        for (a, titles) in other.authors {
            self.authors.entry(a).or_default().extend(titles);
        }
        if let Some(t) = other.first_event {
            self.see_time(t);
        }
        if let Some(t) = other.last_event {
            self.see_time(t);
        }
        for (f, n) in other.formats {
            *self.formats.entry(f).or_default() += n;
        }
        self.correlation_hits_skipped += other.correlation_hits_skipped;
    }

    pub fn total_detections(&self) -> usize {
        self.level_counts
            .values()
            .map(|t| t.values().sum::<usize>())
            .sum()
    }

    /// Detections of `level`.
    pub fn detections_at(&self, level: &str) -> usize {
        self.level_counts.get(level).map_or(0, |t| t.values().sum())
    }

    /// Distinct rules of `level` that fired.
    pub fn unique_rules_at(&self, level: &str) -> usize {
        self.level_counts.get(level).map_or(0, BTreeMap::len)
    }

    /// Distinct rules that fired, over every level.
    pub fn total_unique_rules(&self) -> usize {
        self.level_counts.values().map(BTreeMap::len).sum()
    }

    /// The `n` rules of `level` with the most detections, most first; equal counts are ordered by
    /// title so identical runs print identical tables.
    pub fn top_alerts(&self, level: &str, n: usize) -> Vec<(&str, usize)> {
        let mut hits: Vec<(&str, usize)> = self
            .level_counts
            .get(level)
            .map(|t| t.iter().map(|(title, c)| (title.as_str(), *c)).collect())
            .unwrap_or_default();
        hits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        hits.truncate(n);
        hits
    }

    /// The date (in the output timezone) with the most detections of `level`; the earliest date
    /// wins a tie.
    pub fn busiest_date(&self, level: &str) -> Option<(&str, usize)> {
        let mut best: Option<(&str, usize)> = None;
        // BTreeMap iterates dates in ascending order, so `>` keeps the earliest on a tie.
        for (date, n) in self.date_counts.get(level)? {
            if best.is_none_or(|(_, b)| *n > b) {
                best = Some((date.as_str(), *n));
            }
        }
        best
    }

    /// Individual author names with the number of their distinct rules that fired, most first,
    /// equal counts by name. A rule's `author` field may name several people
    /// (`Florian Roth (Nextron Systems), Zach Mathis (@yamatosecurity)`); it is split like
    /// Hayabusa splits it, so every person is counted once.
    pub fn author_counts(&self) -> Vec<(String, usize)> {
        let mut per_name: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for (author, titles) in &self.authors {
            for name in split_author_names(author) {
                per_name
                    .entry(name)
                    .or_default()
                    .extend(titles.iter().map(String::as_str));
            }
        }
        let mut counts: Vec<(String, usize)> = per_name
            .into_iter()
            .map(|(name, titles)| (name, titles.len()))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        counts
    }
}

/// The individual names in a rule's `author` field: parenthesized remarks are dropped
/// (`Zach Mathis (@yamatosecurity)` → `Zach Mathis`), the rest is split at `,` and `;`, quotes
/// are removed and blank names skipped. The order of first appearance is kept.
pub fn split_author_names(author: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for segment in strip_parenthesized(author).split([',', ';']) {
        let name = segment.replace(['"', '\''], "");
        let name = name.trim();
        if !name.is_empty() && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// `s` without its parenthesized parts (nesting allowed, an unmatched `)` is dropped).
fn strip_parenthesized(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// An author name cut to the table's budget, counted in characters so a multibyte name is never
/// sliced inside a code point.
fn truncate_author(name: &str) -> String {
    if name.chars().count() <= AUTHOR_NAME_MAX_CHARS {
        name.to_string()
    } else {
        format!(
            "{}...",
            name.chars()
                .take(AUTHOR_NAME_KEEP_CHARS)
                .collect::<String>()
        )
    }
}

/// `count` as a percentage of `total`; `0.0` for an empty total so the summary never prints NaN.
fn percentage(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 * 100.0 / total as f64
    }
}

/// Events without a hit and their share of all events (saturating: a hit count above the event
/// count must not underflow).
fn data_reduction(total_events: usize, events_with_hits: usize) -> (usize, f64) {
    let reduction = total_events.saturating_sub(events_with_hits);
    (reduction, percentage(reduction, total_events))
}

/// Columns of the rule authors table for a terminal width (Hayabusa's thresholds): a 2-column
/// table needs about 73 characters, so narrower terminals get a single column.
pub fn author_table_columns(terminal_width: usize) -> usize {
    match terminal_width {
        0..=72 => 1,
        73..=105 => 2,
        106..=139 => 3,
        140..=174 => 4,
        175..=210 => 5,
        _ => 6,
    }
}

fn terminal_width() -> usize {
    match terminal_size::terminal_size() {
        Some((terminal_size::Width(w), _)) => usize::from(w),
        None => DEFAULT_TERMINAL_WIDTH,
    }
}

/// Print the results summary in the Hayabusa/Suzaku style.
pub fn print_summary(summary: &Summary, no_color: bool, utc: bool) {
    let choice = if no_color {
        ColorChoice::Never
    } else {
        ColorChoice::Always
    };
    let wtr = BufferWriter::stdout(choice);
    let mut buf = wtr.buffer();
    let columns = author_table_columns(terminal_width());
    // A closed pipe is not an error of the run; the sibling tools ignore it the same way.
    if write_summary(&mut buf, summary, no_color, utc, columns).is_ok() {
        wtr.print(&buf).ok();
    }
}

/// Write the whole summary to `w`. `author_columns` is the column count of the authors table
/// (see [`author_table_columns`]).
pub fn write_summary<W: WriteColor>(
    w: &mut W,
    summary: &Summary,
    no_color: bool,
    utc: bool,
    author_columns: usize,
) -> io::Result<()> {
    write_header(w, summary, no_color)?;
    write_levels(w, summary, no_color)?;
    write_event_times(w, summary, utc)?;
    write_busiest_dates(w, summary, no_color)?;
    write_top_alerts(w, summary, no_color)?;
    write_rule_authors(w, summary, no_color, author_columns)?;
    write_scan_counts(w, summary, no_color)
}

/// `text` in `color` (no escape codes at all when the color is `None`).
fn paint<W: WriteColor>(w: &mut W, color: Option<Color>, text: &str) -> io::Result<()> {
    match color {
        Some(_) => {
            w.set_color(ColorSpec::new().set_fg(color))?;
            write!(w, "{text}")?;
            w.reset()
        }
        None => write!(w, "{text}"),
    }
}

fn write_header<W: WriteColor>(w: &mut W, s: &Summary, no_color: bool) -> io::Result<()> {
    let green = IwatobiColor::Green.rdg(no_color);
    paint(w, green, "Results Summary:")?;
    writeln!(w)?;
    writeln!(w)?;
    paint(w, green, "Events with hits")?;
    write!(w, " / ")?;
    paint(w, green, "Total events: ")?;
    paint(
        w,
        IwatobiColor::Yellow.rdg(no_color),
        &fmt_num(s.events_with_hits),
    )?;
    write!(w, " / ")?;
    paint(
        w,
        IwatobiColor::Cyan.rdg(no_color),
        &fmt_num(s.total_events),
    )?;
    let (reduction, pct) = data_reduction(s.total_events, s.events_with_hits);
    write!(w, " (")?;
    paint(
        w,
        green,
        &format!("Data reduction: {} events ({pct:.2}%)", fmt_num(reduction)),
    )?;
    writeln!(w, ")")?;
    writeln!(w)
}

fn write_levels<W: WriteColor>(w: &mut W, s: &Summary, no_color: bool) -> io::Result<()> {
    let total = s.total_detections();
    let unique = s.total_unique_rules();
    for level in LEVELS {
        let n = s.detections_at(level);
        let u = s.unique_rules_at(level);
        let line = format!(
            "Total | Unique {level} detections: {} ({:.2}%) | {} ({:.2}%)",
            fmt_num(n),
            percentage(n, total),
            fmt_num(u),
            percentage(u, unique)
        );
        paint(w, IwatobiColor::for_level(level).rdg(no_color), &line)?;
        writeln!(w)?;
    }
    writeln!(w)
}

fn write_event_times<W: WriteColor>(w: &mut W, s: &Summary, utc: bool) -> io::Result<()> {
    if let Some(t) = s.first_event {
        writeln!(w, "First event time: {}", format_timestamp(&t, utc))?;
    }
    if let Some(t) = s.last_event {
        writeln!(w, "Last event time: {}", format_timestamp(&t, utc))?;
    }
    if s.first_event.is_some() || s.last_event.is_some() {
        writeln!(w)?;
    }
    Ok(())
}

fn write_busiest_dates<W: WriteColor>(w: &mut W, s: &Summary, no_color: bool) -> io::Result<()> {
    writeln!(w, "Dates with most total detections:")?;
    for (i, level) in LEVELS.iter().enumerate() {
        if i > 0 {
            write!(w, ", ")?;
        }
        let text = match s.busiest_date(level) {
            Some((date, n)) => format!("{level}: {date} ({})", fmt_num(n)),
            None => format!("{level}: n/a"),
        };
        paint(w, IwatobiColor::for_level(level).rdg(no_color), &text)?;
    }
    writeln!(w)?;
    writeln!(w)
}

/// A table in the look of the sibling tools: rounded corners, no vertical lines inside, plain
/// horizontal rules without junction marks.
fn sibling_table() -> Table {
    let mut style: TableStyle = UTF8_FULL.with_rounded_corners();
    style.header_lines.junction = Some(' ');
    style.content_lines.junction = Some(' ');
    style.top_border.junction = style.top_border.fill;
    style.row_separator.junction = style.row_separator.fill;
    style.bottom_border.junction = style.bottom_border.fill;
    let mut table = Table::new();
    table.load_style(style);
    table
}

/// A table cell in the color of `level` (plain with `-K` and for `informational`).
fn level_cell(text: String, level: &str, no_color: bool) -> Cell {
    let cell = Cell::new(text);
    let color = IwatobiColor::for_level(level);
    if color.rdg(no_color).is_some() {
        cell.fg(color.table_color())
    } else {
        cell
    }
}

fn write_top_alerts<W: WriteColor>(w: &mut W, s: &Summary, no_color: bool) -> io::Result<()> {
    let mut table = sibling_table();
    for pair in LEVELS.chunks(2) {
        let heads: Vec<Cell> = pair
            .iter()
            .map(|level| level_cell(format!("Top {level} alerts:"), level, no_color))
            .collect();
        let bodies: Vec<Cell> = pair
            .iter()
            .map(|level| {
                let mut lines: Vec<String> = s
                    .top_alerts(level, TOP_ALERTS)
                    .into_iter()
                    .map(|(title, n)| format!("{} ({})", sanitize_control_chars(title), fmt_num(n)))
                    .collect();
                lines.resize(TOP_ALERTS, "n/a".to_string());
                level_cell(lines.join("\n"), level, no_color)
            })
            .collect();
        table.add_row(heads);
        table.add_row(bodies);
    }
    writeln!(w, "{table}")?;
    writeln!(w)
}

fn write_rule_authors<W: WriteColor>(
    w: &mut W,
    s: &Summary,
    no_color: bool,
    columns: usize,
) -> io::Result<()> {
    let authors = s.author_counts();
    if authors.is_empty() {
        return Ok(());
    }
    paint(w, IwatobiColor::Green.rdg(no_color), "Rule Authors:")?;
    writeln!(w)?;
    // Authors fill the table row by row (most rules first), so each column shows every
    // `columns`-th author, like Suzaku's `print_detected_rule_authors`.
    let columns = columns.max(1);
    let rows = authors.len().div_ceil(columns);
    let mut cells: Vec<Cell> = Vec::new();
    for x in 0..columns {
        let lines: Vec<String> = (0..rows)
            .filter_map(|y| authors.get(y * columns + x))
            .map(|(name, n)| format!("{} ({n})", truncate_author(&sanitize_control_chars(name))))
            .collect();
        if !lines.is_empty() {
            cells.push(Cell::new(lines.join("\n")));
        }
    }
    let mut table = sibling_table();
    table.add_row(cells);
    writeln!(w, "{table}")?;
    writeln!(w)
}

fn write_scan_counts<W: WriteColor>(w: &mut W, s: &Summary, no_color: bool) -> io::Result<()> {
    let green = IwatobiColor::Green.rdg(no_color);
    paint(w, green, "Scanned log files: ")?;
    writeln!(
        w,
        "{} (skipped: {})",
        fmt_num(s.files_scanned),
        fmt_num(s.files_skipped)
    )?;
    if s.correlation_hits_skipped > 0 {
        paint(
            w,
            green,
            "Correlation hits skipped (missing group-by field): ",
        )?;
        writeln!(w, "{}", fmt_num(s.correlation_hits_skipped))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use termcolor::Buffer;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).single().unwrap()
    }

    const AUTHORS: &str = "Florian Roth (Nextron Systems), Zach Mathis (@yamatosecurity)";

    /// 27 detections over 5 rules: 20 + 3 high, 1 critical, 2 medium, 1 low (no author/date).
    fn sample() -> Summary {
        let mut s = Summary {
            total_events: 1000,
            events_with_hits: 30,
            files_scanned: 5,
            files_skipped: 1,
            correlation_hits_skipped: 2,
            ..Summary::default()
        };
        for _ in 0..20 {
            s.record(
                "high",
                "PHP Memory Exhausted",
                Some("Yamato Security"),
                Some("2026-10-24"),
            );
        }
        for _ in 0..3 {
            s.record(
                "high",
                "Shell Error Output",
                Some("Yamato Security"),
                Some("2026-10-25"),
            );
        }
        s.record(
            "critical",
            "PHP2Shell Exploitation Chain",
            Some("Yamato Security"),
            Some("2026-10-24"),
        );
        // two dates with one detection each: the earliest wins the tie
        s.record(
            "medium",
            "Modifying Crontab",
            Some(AUTHORS),
            Some("2026-10-27"),
        );
        s.record(
            "medium",
            "Modifying Crontab",
            Some(AUTHORS),
            Some("2026-10-26"),
        );
        s.record("low", "Quiet Rule", None, None);
        s.see_time(utc(2026, 10, 27, 1, 2, 3));
        s.see_time(utc(2026, 10, 24, 15, 35, 32) + chrono::Duration::milliseconds(869));
        s
    }

    fn render(s: &Summary, no_color: bool, columns: usize) -> String {
        let mut buf = if no_color {
            Buffer::no_color()
        } else {
            Buffer::ansi()
        };
        write_summary(&mut buf, s, no_color, true, columns).unwrap();
        String::from_utf8(buf.into_inner()).unwrap()
    }

    #[test]
    fn header_levels_times_and_dates() {
        let text = render(&sample(), true, 2);
        assert!(
            text.starts_with(
                "Results Summary:\n\nEvents with hits / Total events: 30 / 1,000 (Data reduction: 970 events (97.00%))\n\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "Total | Unique critical detections: 1 (3.70%) | 1 (20.00%)\n\
                 Total | Unique high detections: 23 (85.19%) | 2 (40.00%)\n\
                 Total | Unique medium detections: 2 (7.41%) | 1 (20.00%)\n\
                 Total | Unique low detections: 1 (3.70%) | 1 (20.00%)\n\
                 Total | Unique informational detections: 0 (0.00%) | 0 (0.00%)\n\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "First event time: 2026-10-24 15:35:32.869 +00:00\nLast event time: 2026-10-27 01:02:03.000 +00:00\n\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "Dates with most total detections:\ncritical: 2026-10-24 (1), high: 2026-10-24 (20), medium: 2026-10-26 (1), low: n/a, informational: n/a\n\n"
            ),
            "{text}"
        );
        assert!(
            text.ends_with(
                "Scanned log files: 5 (skipped: 1)\nCorrelation hits skipped (missing group-by field): 2\n"
            ),
            "{text}"
        );
        assert!(
            !text.contains('\u{1b}'),
            "no escape codes with -K: {text:?}"
        );
    }

    #[test]
    fn event_times_honor_utc_flag() {
        let s = sample();
        let mut buf = Buffer::no_color();
        write_summary(&mut buf, &s, true, false, 2).unwrap();
        let text = String::from_utf8(buf.into_inner()).unwrap();
        let first = s.first_event.unwrap();
        assert!(
            text.contains(&format!(
                "First event time: {}\n",
                format_timestamp(&first, false)
            )),
            "{text}"
        );
    }

    #[test]
    fn top_alerts_table_lists_five_per_level_two_levels_per_row() {
        let text = render(&sample(), true, 2);
        let table_start = text.find('╭').expect("rounded top-left corner");
        let table = &text[table_start..];
        let lines: Vec<&str> = table.lines().collect();
        // header row of the first chunk: critical and high side by side
        let head = lines
            .iter()
            .find(|l| l.contains("Top critical alerts:"))
            .unwrap();
        assert!(head.contains("Top high alerts:"), "{head}");
        let body: Vec<&&str> = lines
            .iter()
            .filter(|l| l.contains("PHP2Shell Exploitation Chain (1)"))
            .collect();
        assert_eq!(body.len(), 1);
        assert!(body[0].contains("PHP Memory Exhausted (20)"), "{}", body[0]);
        // the second high rule sits on the next line next to the critical n/a padding
        let second = lines
            .iter()
            .find(|l| l.contains("Shell Error Output (3)"))
            .unwrap();
        assert!(second.contains("n/a"), "{second}");
        let medium = lines
            .iter()
            .find(|l| l.contains("Top medium alerts:"))
            .unwrap();
        assert!(medium.contains("Top low alerts:"), "{medium}");
        assert!(lines.iter().any(|l| l.contains("Modifying Crontab (2)")));
        assert!(lines.iter().any(|l| l.contains("Quiet Rule (1)")));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Top informational alerts:"))
        );
        // five lines per level: the informational column is all n/a
        let na_rows = lines
            .iter()
            .filter(|l| l.trim_matches(['│', ' ']) == "n/a")
            .count();
        assert_eq!(na_rows, 5, "{table}");
        // the sibling look: rounded corners, no inner vertical lines or junction marks
        assert!(table.contains('╮') && table.contains('╰') && table.contains('╯'));
        for forbidden in ['┆', '┼', '┬', '┴', '┌', '┐', '└', '┘'] {
            assert!(!table.contains(forbidden), "{forbidden} in\n{table}");
        }
    }

    #[test]
    fn rule_authors_table_splits_names_and_fills_columns_row_by_row() {
        let text = render(&sample(), true, 2);
        let start = text.find("Rule Authors:").expect("authors heading");
        let section = &text[start..];
        // Yamato Security (3 rules) first, then the two single-rule authors by name; with two
        // columns the third author goes under the first.
        assert!(section.contains("Yamato Security (3)"), "{section}");
        assert!(section.contains("Florian Roth (1)"), "{section}");
        assert!(section.contains("Zach Mathis (1)"), "{section}");
        assert!(!section.contains("Nextron"), "{section}");
        assert!(!section.contains("@yamatosecurity"), "{section}");
        let yamato = section
            .lines()
            .find(|l| l.contains("Yamato Security (3)"))
            .unwrap();
        assert!(yamato.contains("Florian Roth (1)"), "{yamato}");
        let zach = section
            .lines()
            .find(|l| l.contains("Zach Mathis (1)"))
            .unwrap();
        assert!(!zach.contains("Florian"), "{zach}");
        // a single column stacks everyone
        let one = render(&sample(), true, 1);
        let start = one.find("Rule Authors:").unwrap();
        let section = &one[start..];
        let yamato = section
            .lines()
            .find(|l| l.contains("Yamato Security (3)"))
            .unwrap();
        assert!(!yamato.contains("Florian"), "{yamato}");
        // the authors section comes after the alerts table and before the file counts
        assert!(text.find("Top critical alerts:").unwrap() < text.find("Rule Authors:").unwrap());
        assert!(text.find("Rule Authors:").unwrap() < text.find("Scanned log files:").unwrap());
    }

    #[test]
    fn colors_follow_the_level_palette_and_vanish_with_no_color() {
        let colored = render(&sample(), false, 2);
        assert!(
            colored.contains("\u{1b}[38;2;0;255;0mResults Summary:\u{1b}[0m\n"),
            "{colored:?}"
        );
        assert!(colored.contains("\u{1b}[38;2;255;0;0mTotal | Unique critical detections"));
        assert!(colored.contains("\u{1b}[38;2;255;175;0mTotal | Unique high detections"));
        assert!(colored.contains("\u{1b}[38;2;255;255;0mTotal | Unique medium detections"));
        assert!(colored.contains("\u{1b}[38;2;0;255;0mTotal | Unique low detections"));
        // informational is the default color: no escape right before it
        assert!(
            colored.contains("\u{1b}[0m\nTotal | Unique informational detections"),
            "{colored:?}"
        );
        assert!(
            colored.contains("\u{1b}[38;2;255;255;0m30\u{1b}[0m / "),
            "{colored:?}"
        );
        assert!(
            colored.contains("\u{1b}[38;2;0;255;255m1,000\u{1b}[0m ("),
            "{colored:?}"
        );
        assert!(colored.contains("\u{1b}[38;2;255;175;0mhigh: 2026-10-24 (20)\u{1b}[0m, "));
        assert!(
            colored.contains("\u{1b}[38;2;0;255;0mScanned log files: \u{1b}[0m5 (skipped: 1)\n")
        );
        let plain = render(&sample(), true, 2);
        assert!(!plain.contains('\u{1b}'));
        // the same words in both
        let strip = |s: &str| {
            let mut out = String::new();
            let mut chars = s.chars();
            while let Some(c) = chars.next() {
                if c == '\u{1b}' {
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        assert_eq!(strip(&colored), plain);
    }

    #[test]
    fn empty_summary_prints_zeroes_and_skips_optional_sections() {
        let text = render(&Summary::default(), true, 2);
        assert!(text.contains(
            "Events with hits / Total events: 0 / 0 (Data reduction: 0 events (0.00%))\n"
        ));
        for level in LEVELS {
            assert!(text.contains(&format!(
                "Total | Unique {level} detections: 0 (0.00%) | 0 (0.00%)\n"
            )));
        }
        assert!(!text.contains("First event time"));
        assert!(!text.contains("Last event time"));
        assert!(
            text.contains("critical: n/a, high: n/a, medium: n/a, low: n/a, informational: n/a\n")
        );
        assert!(text.contains("Top critical alerts:"));
        assert!(!text.contains("Rule Authors:"));
        assert!(!text.contains("Correlation hits skipped"));
        assert!(
            text.ends_with("Scanned log files: 0 (skipped: 0)\n"),
            "{text}"
        );
    }

    #[test]
    fn rule_titles_and_authors_are_sanitized_in_the_tables() {
        let mut s = Summary::default();
        s.record(
            "high",
            "Evil\u{1b}]0;pwned\u{7} Title",
            Some("Mallory\u{1b}[31m"),
            Some("2026-10-24"),
        );
        let text = render(&s, true, 2);
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{7}'),
            "{text:?}"
        );
        assert!(text.contains("Evil\\x1B]0;pwned\\x07 Title (1)"), "{text}");
        assert!(text.contains("Mallory\\x1B[31m (1)"), "{text}");
    }

    #[test]
    fn top_alerts_sort_by_count_then_title_and_truncate() {
        let mut s = Summary::default();
        for (title, n) in [
            ("Zeta", 2),
            ("Many", 9),
            ("Alpha", 2),
            ("Mid", 5),
            ("Beta", 2),
            ("Gamma", 1),
        ] {
            for _ in 0..n {
                s.record("low", title, None, None);
            }
        }
        assert_eq!(
            s.top_alerts("low", 5),
            vec![
                ("Many", 9),
                ("Mid", 5),
                ("Alpha", 2),
                ("Beta", 2),
                ("Zeta", 2)
            ]
        );
        assert_eq!(s.top_alerts("low", 2), vec![("Many", 9), ("Mid", 5)]);
        assert!(s.top_alerts("high", 5).is_empty());
        assert_eq!(s.detections_at("low"), 21);
        assert_eq!(s.unique_rules_at("low"), 6);
        assert_eq!(s.total_unique_rules(), 6);
        assert_eq!(s.total_detections(), 21);
    }

    #[test]
    fn busiest_date_takes_the_earliest_on_a_tie() {
        let mut s = Summary::default();
        for date in [
            "2026-10-27",
            "2026-10-25",
            "2026-10-26",
            "2026-10-25",
            "2026-10-27",
        ] {
            s.record("medium", "r", None, Some(date));
        }
        assert_eq!(s.busiest_date("medium"), Some(("2026-10-25", 2)));
        assert_eq!(s.busiest_date("high"), None);
        s.record("high", "r", None, None);
        assert_eq!(s.busiest_date("high"), None, "a detection without a date");
    }

    #[test]
    fn author_names_are_split_like_hayabusa() {
        assert_eq!(
            split_author_names(AUTHORS),
            vec!["Florian Roth", "Zach Mathis"]
        );
        assert_eq!(
            split_author_names("Yamato Security"),
            vec!["Yamato Security"]
        );
        assert_eq!(
            split_author_names("a; b (x, y); 'c', \"a\""),
            vec!["a", "b", "c"]
        );
        assert_eq!(split_author_names("(anonymous)"), Vec::<String>::new());
        assert_eq!(split_author_names("   "), Vec::<String>::new());
        assert_eq!(split_author_names("x) y"), vec!["x y"]);
        assert_eq!(split_author_names("nested (a (b) c) d"), vec!["nested  d"]);
        let mut s = Summary::default();
        s.record("low", "r1", Some("A, B"), None);
        s.record("low", "r2", Some("B"), None);
        s.record("low", "r2", Some("B"), None);
        s.record("low", "r3", Some("C (@c)"), None);
        assert_eq!(
            s.author_counts(),
            vec![
                ("B".to_string(), 2),
                ("A".to_string(), 1),
                ("C".to_string(), 1)
            ]
        );
    }

    #[test]
    fn author_truncation_counts_characters() {
        assert_eq!(truncate_author("Zach Mathis"), "Zach Mathis");
        assert_eq!(truncate_author("山本太郎"), "山本太郎");
        let exact: String = "x".repeat(27);
        assert_eq!(truncate_author(&exact), exact);
        let long = truncate_author(&"a".repeat(40));
        assert_eq!(long, format!("{}...", "a".repeat(24)));
        assert_eq!(long.chars().count(), 27);
        let name = format!("{}{}", "x".repeat(22), "あ".repeat(10));
        assert!(!name.is_char_boundary(24));
        let out = truncate_author(&name);
        assert!(out.ends_with("..."));
        assert_eq!(out.chars().count(), 27);
    }

    #[test]
    fn percentages_and_reduction_never_divide_by_zero() {
        assert_eq!(percentage(0, 0), 0.0);
        assert_eq!(percentage(1, 4), 25.0);
        assert_eq!(format!("{:.2}", percentage(11_807, 2_332_963)), "0.51");
        assert_eq!(data_reduction(100, 5), (95, 95.0));
        assert_eq!(data_reduction(1, 2), (0, 0.0));
        let (n, pct) = data_reduction(0, 0);
        assert_eq!(n, 0);
        assert_eq!(pct, 0.0);
    }

    #[test]
    fn author_table_columns_follow_the_terminal_width() {
        assert_eq!(author_table_columns(0), 1);
        assert_eq!(author_table_columns(72), 1);
        assert_eq!(author_table_columns(73), 2);
        assert_eq!(author_table_columns(100), 2);
        assert_eq!(author_table_columns(105), 2);
        assert_eq!(author_table_columns(106), 3);
        assert_eq!(author_table_columns(139), 3);
        assert_eq!(author_table_columns(140), 4);
        assert_eq!(author_table_columns(174), 4);
        assert_eq!(author_table_columns(175), 5);
        assert_eq!(author_table_columns(210), 5);
        assert_eq!(author_table_columns(211), 6);
        assert_eq!(author_table_columns(1000), 6);
    }

    #[test]
    fn many_authors_fill_every_column() {
        let mut s = Summary::default();
        for i in 0..7 {
            s.record(
                "low",
                &format!("rule {i}"),
                Some(&format!("author{i}")),
                None,
            );
        }
        let text = render(&s, true, 3);
        let start = text.find("Rule Authors:").unwrap();
        let section = &text[start..];
        // 7 authors over 3 columns = 3 rows: author0 author1 author2 / author3 author4 author5 / author6
        let first = section.lines().find(|l| l.contains("author0 (1)")).unwrap();
        assert!(
            first.contains("author1 (1)") && first.contains("author2 (1)"),
            "{first}"
        );
        let last = section.lines().find(|l| l.contains("author6 (1)")).unwrap();
        assert!(!last.contains("author5"), "{last}");
        // a zero column count is treated as one column
        let one = render(&s, true, 0);
        let start = one.find("Rule Authors:").unwrap();
        let line = one[start..]
            .lines()
            .find(|l| l.contains("author0 (1)"))
            .unwrap();
        assert!(!line.contains("author1"), "{line}");
    }

    #[test]
    fn merge_and_see_time_keep_the_extremes() {
        let mut a = sample();
        let mut b = Summary {
            total_events: 5,
            events_with_hits: 1,
            files_scanned: 2,
            files_skipped: 3,
            correlation_hits_skipped: 4,
            ..Summary::default()
        };
        b.record(
            "high",
            "PHP Memory Exhausted",
            Some("Yamato Security"),
            Some("2026-10-24"),
        );
        b.record(
            "informational",
            "Info Rule",
            Some("Someone"),
            Some("2026-10-20"),
        );
        b.see_time(utc(2026, 10, 20, 0, 0, 0));
        *b.formats.entry("syslog".to_string()).or_default() += 1;
        a.merge(b);
        assert_eq!(a.total_events, 1005);
        assert_eq!(a.events_with_hits, 31);
        assert_eq!(a.files_scanned, 7);
        assert_eq!(a.files_skipped, 4);
        assert_eq!(a.correlation_hits_skipped, 6);
        assert_eq!(a.detections_at("high"), 24);
        assert_eq!(a.detections_at("informational"), 1);
        assert_eq!(a.first_event, Some(utc(2026, 10, 20, 0, 0, 0)));
        assert_eq!(a.last_event, Some(utc(2026, 10, 27, 1, 2, 3)));
        assert_eq!(a.formats["syslog"], 1);
        assert_eq!(a.busiest_date("high"), Some(("2026-10-24", 21)));
        let text = render(&a, true, 2);
        assert!(text.contains("informational: 2026-10-20 (1)\n"));
        assert!(text.contains("Someone (1)"));
    }
}
