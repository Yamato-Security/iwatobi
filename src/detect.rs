//! Scanning one target: lines → events → rule matches (design §8).

use crate::correlate::{BaseHit, make_base_hit};
use crate::event::ParsedEvent;
use crate::input::{self, ScanTarget, SkipReason};
use crate::parsers::layout::FormatRegistry;
use crate::parsers::{self, FileFormat, ParseContext, TzAssumption};
use crate::rules::RuleSet;
use crate::summary::Summary;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// One rule match.
#[derive(Clone, Debug)]
pub struct Detection {
    pub event: ParsedEvent,
    /// Index into `RuleSet::rules`.
    pub rule_index: usize,
    pub file: Arc<str>,
    pub line: usize,
}

/// Event-time filter from `--timeline-start/--timeline-end/--time-offset`.
#[derive(Clone, Debug, Default)]
pub struct TimeFilter {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

impl TimeFilter {
    /// Events without a timestamp pass.
    pub fn accepts(&self, t: Option<DateTime<Utc>>) -> bool {
        match t {
            None => true,
            Some(t) => self.start.is_none_or(|s| t >= s) && self.end.is_none_or(|e| t <= e),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub tz: TzAssumption,
    pub hostname_hint: Option<String>,
    pub time_filter: TimeFilter,
    /// The custom formats of `config/custom_log_formats.yaml` (or `--custom-formats`).
    pub custom_formats: Arc<FormatRegistry>,
}

/// What scanning one target produced.
#[derive(Default)]
pub struct ScanResult {
    pub detections: Vec<Detection>,
    pub base_hits: Vec<BaseHit>,
    pub summary: Summary,
    pub format: Option<FileFormat>,
    pub skipped: Option<SkipReason>,
    /// True when at least one event carried its own zone and at least one did not (amendment A7).
    pub mixed_zone_sources: bool,
    pub events: usize,
    /// A read error (truncated or corrupt `.gz`, I/O error) ended the file early.
    pub read_error: Option<String>,
}

/// Scan one file (or stream) against the rule set.
pub fn scan_target(target: &ScanTarget, ruleset: &RuleSet, opts: &ScanOptions) -> ScanResult {
    let mut result = ScanResult::default();
    if let Some(reason) = input::quick_skip_reason(&target.path) {
        result.skipped = Some(reason);
        result.summary.files_skipped = 1;
        return result;
    }
    let (sample, binary) = match input::read_sample(&target.path, 64) {
        Ok(s) => s,
        Err(e) => {
            result.skipped = Some(SkipReason::Unreadable(e.to_string()));
            result.summary.files_skipped = 1;
            return result;
        }
    };
    if binary {
        result.skipped = Some(SkipReason::Binary);
        result.summary.files_skipped = 1;
        return result;
    }
    let mut ctx = ParseContext::new(&target.path, opts.tz);
    ctx.display_name = target.display_name.clone();
    ctx.hostname_hint = opts.hostname_hint.clone();
    ctx.extra_tags = target.extra_tags.clone();
    let format =
        match target.format.clone().or_else(|| {
            parsers::detect_format(&sample, &ctx.hints, &target.path, &opts.custom_formats)
        }) {
            Some(f) => f,
            None => {
                result.skipped = Some(SkipReason::UnrecognizedFormat);
                result.summary.files_skipped = 1;
                return result;
            }
        };
    result.format = Some(format.clone());
    let reader = match input::open_reader(&target.path) {
        Ok(r) => r,
        Err(e) => {
            result.skipped = Some(SkipReason::Unreadable(e.to_string()));
            result.summary.files_skipped = 1;
            return result;
        }
    };
    let mut read_error = None;
    let mut line_no = 0usize;
    let lines = input::lines(reader).map_while(|line| match line {
        Ok(l) => {
            line_no += 1;
            Some(l)
        }
        Err(e) => {
            read_error = Some(format!("read error after line {line_no}: {e}"));
            None
        }
    });
    scan_lines(lines, &format, ctx, target, ruleset, opts, &mut result);
    result.read_error = read_error;
    result
}

/// Scan an iterator of lines (used for files and for the journalctl stream).
pub fn scan_lines<I: Iterator<Item = String>>(
    lines: I,
    format: &FileFormat,
    ctx: ParseContext,
    target: &ScanTarget,
    ruleset: &RuleSet,
    opts: &ScanOptions,
    result: &mut ScanResult,
) {
    let file: Arc<str> = Arc::from(target.display_name.as_str());
    let mut parser = parsers::parser_for(format, ctx);
    result.summary.files_scanned = 1;
    *result.summary.formats.entry(format.name()).or_default() += 1;
    let mut saw_zoned = false;
    let mut saw_naive = false;
    for (idx, line) in lines.enumerate() {
        let Some(event) = parser.parse_line(&line) else {
            continue;
        };
        let ts_utc = event.timestamp.map(|t| t.with_timezone(&Utc));
        if !opts.time_filter.accepts(ts_utc) {
            continue;
        }
        result.events += 1;
        result.summary.total_events += 1;
        if let Some(t) = ts_utc {
            result.summary.see_time(t);
            if event.timestamp_inferred {
                // borrowed timestamps say nothing about the source's zone handling
            } else if event.tz_explicit {
                saw_zoned = true;
            } else {
                saw_naive = true;
            }
        }
        let sigma_event = event.to_sigma_event();
        let mut hit = false;
        for (i, lr) in ruleset.rules.iter().enumerate() {
            if lr.logsource.matches_any(&event.tags) && lr.rule.is_match(&sigma_event) {
                hit = true;
                result.detections.push(Detection {
                    event: event.clone(),
                    rule_index: i,
                    file: file.clone(),
                    line: idx + 1,
                });
            }
        }
        for (ci, corr) in ruleset.correlations.iter().enumerate() {
            for (bi, base) in corr.base_rules.iter().enumerate() {
                if !(base.logsource.matches_any(&event.tags) && base.rule.is_match(&sigma_event)) {
                    continue;
                }
                // A correlation base match is a hit of the event even when no correlation fires.
                hit = true;
                // Only an event with a time can take part in a time window.
                let Some(ts) = ts_utc else { continue };
                let summary = format!("{} ({}:{})", base.meta.title, file, idx + 1);
                let mut base_hit = make_base_hit(corr, ci, bi, &sigma_event, &event, ts, summary);
                base_hit.file = file.clone();
                base_hit.line = idx + 1;
                result.base_hits.push(base_hit);
            }
        }
        if hit {
            result.summary.events_with_hits += 1;
        }
    }
    result.mixed_zone_sources = saw_zoned && saw_naive;
}
