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

//! Sigma correlation evaluation with sliding windows (amendment A12).
//!
//! sigma-rust is used only to parse `SigmaCorrelationRule`; its engine buckets events into fixed,
//! epoch-aligned windows, which misses a chain that crosses a window boundary (the honeypot case
//! B15: crash 17:34:43, OOM 17:34:45, session 17:35:01 with `timespan: 5m` straddles 17:35:00).
//! Here the base-rule hits of each correlation are grouped by their `group-by` values, sorted by
//! time and a window of `timespan` slides over them.
//!
//! Semantics, per correlation rule and per group-by value tuple (hits sorted by timestamp, ties by
//! base-rule index, then by arrival order):
//!
//! - The window starting at hit *i* is `[t_i, t_i + timespan]`, both ends inclusive.
//! - `event_count`: the number of hits in the window is tested against the condition.
//!   `gte`/`gt`/`eq` are evaluated on the sliding window. `lt`/`lte` cannot be evaluated on a
//!   sliding window (a window holding one hit always satisfies `lt: n`), so a condition that
//!   contains `lt` or `lte` is evaluated on fixed buckets: the timestamp floored to a multiple of
//!   `timespan` since the epoch, exactly like sigma-rust. Only non-empty buckets can be reported.
//! - `value_count`: the number of distinct values of `condition.field` among the hits in the
//!   window (hits without that field are members of the window but contribute no value); the same
//!   `lt`/`lte` rule applies.
//! - `temporal`: the window must contain every base rule listed in `rules:`.
//! - `temporal_ordered`: additionally the first occurrence of each base rule inside the window
//!   must appear in `rules:` order (hits with equal timestamps are ordered by base-rule index).
//! - A missing condition on `event_count`/`value_count` is evaluated as `gte: 1` (one warning).
//!
//! Each fired cluster is reported once: when the window starting at *i* fires, every hit in it
//! becomes a member of one [`CorrelationHit`] and the scan continues with the first hit after the
//! window, so reports never overlap and a burst of 4 hits with `gte: 3` is one hit, not two or
//! four. A hit whose event lacks one of the `group-by` fields is dropped and counted in
//! [`CorrelationOutcome::skipped_missing_group_by`]; the run never aborts on a bad hit or rule.

use crate::errorlog::log_warn;
use crate::event::ParsedEvent;
use crate::rules::CorrelationRule;
use chrono::{DateTime, Utc};
use sigma_rust::Event;
use sigma_rust::correlation::{CorrelationCondition, CorrelationType, FieldAliases};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// One base-rule match collected during the scan.
#[derive(Clone, Debug)]
pub struct BaseHit {
    pub correlation_index: usize,
    pub base_index: usize,
    pub timestamp: DateTime<Utc>,
    /// The `group-by` field values, `None` when the event lacks one of them.
    pub group_values: Option<Vec<String>>,
    /// Value of the `value_count` field, if the correlation has one.
    pub value_field: Option<String>,
    pub hostname: Option<String>,
    /// `RuleTitle (file:line)` for the correlation's Details column.
    pub summary: String,
    /// Where the event was read, for a stable order of hits that share a timestamp.
    pub file: Arc<str>,
    pub line: usize,
}

/// A fired correlation.
#[derive(Clone, Debug)]
pub struct CorrelationHit {
    pub correlation_index: usize,
    /// Representative instant: the latest member.
    pub timestamp: DateTime<Utc>,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub count: usize,
    pub group_values: Vec<String>,
    /// Indices into the `hits` slice passed to [`evaluate`].
    pub members: Vec<usize>,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CorrelationOutcome {
    pub hits: Vec<CorrelationHit>,
    /// Base hits dropped because the event lacked a `group-by` field.
    pub skipped_missing_group_by: usize,
}

/// Build a [`BaseHit`] for a base rule that matched `event`.
///
/// `group_values` holds the value of every `group-by` field, each resolved through the
/// correlation's `aliases` (alias name → base rule name → field) for the base rule
/// `corr.base_rules[base_index]`, rendered with `EventValue::value_to_string` (a present field
/// with a null value is the empty string). It is `None` when the event lacks one of the fields;
/// [`evaluate`] then drops and counts the hit. `value_field` is the value of `condition.field`
/// (resolved the same way) when the correlation has one.
pub fn make_base_hit(
    corr: &CorrelationRule,
    correlation_index: usize,
    base_index: usize,
    event: &Event,
    parsed: &ParsedEvent,
    timestamp: DateTime<Utc>,
    summary: String,
) -> BaseHit {
    let section = &corr.spec.correlation;
    let identifiers: &[String] = corr
        .base_rules
        .get(base_index)
        .map(|b| b.identifiers.as_slice())
        .unwrap_or(&[]);
    let aliases = section.aliases.as_ref();
    // A present-but-null value (CLF `-`, a JSON key without a value) is no value: it must not
    // merge unrelated clients into one group or count as a distinct value. sigma-rust renders
    // null as the empty string, which is never a meaningful group or value either.
    let lookup = |field: &str| -> Option<String> {
        event
            .get(resolve_field(field, aliases, identifiers))
            .map(|v| v.value_to_string())
            .filter(|s| !s.is_empty())
    };
    let group_values = section
        .group_by
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|field| lookup(field.as_str()))
        .collect::<Option<Vec<String>>>();
    let value_field = section
        .condition
        .as_ref()
        .and_then(|c| c.field.as_deref())
        .and_then(lookup);
    BaseHit {
        correlation_index,
        base_index,
        timestamp,
        group_values,
        value_field,
        hostname: parsed.hostname.clone(),
        summary,
        file: Arc::from(""),
        line: 0,
    }
}

/// Evaluate every correlation rule over the collected base hits. The returned hits are sorted by
/// timestamp; their `members` index into `hits`.
pub fn evaluate(correlations: &[CorrelationRule], hits: &[BaseHit]) -> CorrelationOutcome {
    evaluate_with(correlations, hits, &mut |msg| log_warn(&msg))
}

/// [`evaluate`] with an explicit sink for the warnings (the error log in production, a `Vec` in
/// the tests), which keeps the evaluation itself free of I/O.
fn evaluate_with(
    correlations: &[CorrelationRule],
    hits: &[BaseHit],
    warn: &mut dyn FnMut(String),
) -> CorrelationOutcome {
    let mut outcome = CorrelationOutcome::default();
    // Hits of each correlation, as indices into `hits` (a hit that names no loaded correlation
    // is ignored; the scanner never produces one).
    let mut per_correlation: Vec<Vec<usize>> = vec![Vec::new(); correlations.len()];
    for (i, hit) in hits.iter().enumerate() {
        if let Some(bucket) = per_correlation.get_mut(hit.correlation_index) {
            bucket.push(i);
        }
    }
    for ((ci, corr), indices) in correlations.iter().enumerate().zip(&per_correlation) {
        if indices.is_empty() {
            continue;
        }
        let Some(plan) = Plan::new(corr, warn) else {
            continue;
        };
        let mut groups: BTreeMap<&[String], Vec<usize>> = BTreeMap::new();
        for &i in indices {
            match &hits[i].group_values {
                None => outcome.skipped_missing_group_by += 1,
                Some(values) => groups.entry(values.as_slice()).or_default().push(i),
            }
        }
        for (key, mut members) in groups {
            // Hits that share a timestamp keep the order they were logged in (file, then line),
            // so `temporal_ordered` judges same-second events by their log order; the base rule
            // index only breaks ties between rules that matched the same event.
            members.sort_by(|&a, &b| {
                let (x, y) = (&hits[a], &hits[b]);
                (x.timestamp, &x.file, x.line, x.base_index).cmp(&(
                    y.timestamp,
                    &y.file,
                    y.line,
                    y.base_index,
                ))
            });
            if plan.fixed_buckets {
                fixed_buckets(ci, &plan, key, &members, hits, &mut outcome.hits);
            } else {
                sliding_window(ci, &plan, key, &members, hits, &mut outcome.hits);
            }
        }
    }
    // Stable, so hits with the same timestamp stay in correlation / group order.
    outcome.hits.sort_by_key(|h| h.timestamp);
    outcome
}

/// The field that carries `field` for a base rule (`aliases: {alias: {rule: field}}`), or `field`
/// itself when no alias applies. The alias may key the rule by any identifier it can be
/// referenced by (the `rules:` entry, `name`, `id` or `title`).
fn resolve_field<'a>(
    field: &'a str,
    aliases: Option<&'a FieldAliases>,
    identifiers: &[String],
) -> &'a str {
    aliases
        .and_then(|a| a.aliases.get(field))
        .and_then(|per_rule| identifiers.iter().find_map(|id| per_rule.get(id)))
        .map(String::as_str)
        .unwrap_or(field)
}

/// How one correlation rule is evaluated, derived from its `correlation:` section.
struct Plan {
    kind: CorrelationType,
    span_secs: i64,
    /// The threshold (synthesized as `gte: 1` when the rule has none).
    condition: CorrelationCondition,
    /// `neq`, which sigma-rust's `CorrelationCondition` does not carry (see `CorrelationRule`).
    neq: Option<u64>,
    /// `lt`/`lte`/`eq`/`neq` thresholds are evaluated on fixed buckets (see the module docs): a
    /// sliding window can always be shrunk or grown, so "exactly n" or "fewer than n" events in
    /// some window says nothing.
    fixed_buckets: bool,
    /// Base-rule indices every window of a temporal correlation must contain, in `rules:` order.
    required: Vec<usize>,
}

impl Plan {
    fn new(corr: &CorrelationRule, warn: &mut dyn FnMut(String)) -> Option<Plan> {
        let section = &corr.spec.correlation;
        let label = format!(
            "Correlation rule '{}' ({})",
            corr.meta.title, corr.meta.rule_file
        );
        let Some(span_secs) = timespan_seconds(&section.timespan) else {
            warn(format!(
                "{label}: invalid timespan '{}'; the rule was not evaluated",
                section.timespan
            ));
            return None;
        };
        let kind = section.correlation_type.clone();
        let counting = matches!(
            kind,
            CorrelationType::EventCount | CorrelationType::ValueCount
        );
        let mut condition = section.condition.clone().unwrap_or_default();
        let neq = corr.condition_neq;
        if counting && !has_threshold(&condition) && neq.is_none() {
            warn(format!(
                "{label}: the {} correlation has no condition; it is evaluated as 'gte: 1'",
                type_name(&kind)
            ));
            condition.gte = Some(1);
        }
        if kind == CorrelationType::ValueCount && condition.field.is_none() {
            warn(format!(
                "{label}: a value_count correlation needs 'field' in its condition; the rule was not evaluated"
            ));
            return None;
        }
        let fixed_buckets = counting
            && (condition.lt.is_some()
                || condition.lte.is_some()
                || condition.eq.is_some()
                || neq.is_some());
        let mut required: Vec<usize> = Vec::new();
        for &r in &corr.rule_order {
            if !required.contains(&r) {
                required.push(r);
            }
        }
        if required.is_empty() {
            required = (0..corr.base_rules.len()).collect();
        }
        if !counting && required.is_empty() {
            warn(format!(
                "{label}: the {} correlation references no base rules; the rule was not evaluated",
                type_name(&kind)
            ));
            return None;
        }
        Some(Plan {
            kind,
            span_secs,
            condition,
            neq,
            fixed_buckets,
            required,
        })
    }
}

fn has_threshold(c: &CorrelationCondition) -> bool {
    c.gte.is_some() || c.gt.is_some() || c.eq.is_some() || c.lt.is_some() || c.lte.is_some()
}

fn type_name(kind: &CorrelationType) -> &'static str {
    match kind {
        CorrelationType::EventCount => "event_count",
        CorrelationType::ValueCount => "value_count",
        CorrelationType::Temporal => "temporal",
        CorrelationType::TemporalOrdered => "temporal_ordered",
    }
}

/// `timespan` in seconds. Same grammar as sigma-rust's `CorrelationEngine::parse_timespan`
/// (an integer followed by `s`, `m`, `h` or `d`), but with checked arithmetic: an absurd value
/// such as `99999999999999999999d` is rejected instead of overflowing.
pub fn timespan_seconds(text: &str) -> Option<i64> {
    let text = text.trim();
    let unit_at = text.find(|c: char| c.is_alphabetic())?;
    let (value, unit) = text.split_at(unit_at);
    let value: u64 = value.parse().ok()?;
    let unit_secs: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    i64::try_from(value.checked_mul(unit_secs)?).ok()
}

/// Inclusive end of the window that starts at `start`.
fn window_end(start: DateTime<Utc>, span_secs: i64) -> DateTime<Utc> {
    chrono::Duration::try_seconds(span_secs)
        .and_then(|span| start.checked_add_signed(span))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// Start of the fixed, epoch-aligned bucket of `span_secs` that holds `t` (seconds, nanoseconds).
/// A zero timespan makes every distinct instant its own bucket.
fn bucket_key(t: DateTime<Utc>, span_secs: i64) -> (i64, u32) {
    if span_secs <= 0 {
        (t.timestamp(), t.timestamp_subsec_nanos())
    } else {
        (t.timestamp().div_euclid(span_secs) * span_secs, 0)
    }
}

/// Slide a window of `timespan` over one group's hits (`sorted`: indices into `hits`, in time
/// order) and report every fired cluster once.
fn sliding_window(
    ci: usize,
    plan: &Plan,
    key: &[String],
    sorted: &[usize],
    hits: &[BaseHit],
    out: &mut Vec<CorrelationHit>,
) {
    let mut state = WindowState::default();
    let mut i = 0;
    // Exclusive end of the window: the window starting at `i` is `sorted[i..j]`.
    let mut j = 0;
    while i < sorted.len() {
        let end = window_end(hits[sorted[i]].timestamp, plan.span_secs);
        while j < sorted.len() && hits[sorted[j]].timestamp <= end {
            state.add(j, &hits[sorted[j]]);
            j += 1;
        }
        // `sorted[i]` lies inside its own window, so `j > i` here.
        if state.fires(plan, j - i) {
            if let Some(hit) = make_hit(ci, key, &sorted[i..j], hits) {
                out.push(hit);
            }
            state.clear();
            i = j;
        } else {
            state.remove(i, &hits[sorted[i]]);
            i += 1;
        }
    }
}

/// Evaluate an `event_count`/`value_count` condition with `lt`/`lte` on fixed buckets.
fn fixed_buckets(
    ci: usize,
    plan: &Plan,
    key: &[String],
    sorted: &[usize],
    hits: &[BaseHit],
    out: &mut Vec<CorrelationHit>,
) {
    let mut start = 0;
    while start < sorted.len() {
        let bucket = bucket_key(hits[sorted[start]].timestamp, plan.span_secs);
        let mut end = start + 1;
        while end < sorted.len()
            && bucket_key(hits[sorted[end]].timestamp, plan.span_secs) == bucket
        {
            end += 1;
        }
        let members = &sorted[start..end];
        let count = match plan.kind {
            CorrelationType::ValueCount => distinct_values(members, hits),
            _ => members.len(),
        };
        let count = count as u64;
        let threshold_ok = (!has_threshold(&plan.condition) || plan.condition.matches(count))
            && plan.neq.is_none_or(|n| count != n);
        if threshold_ok && let Some(hit) = make_hit(ci, key, members, hits) {
            out.push(hit);
        }
        start = end;
    }
}

fn distinct_values(members: &[usize], hits: &[BaseHit]) -> usize {
    members
        .iter()
        .filter_map(|&m| hits[m].value_field.as_deref())
        .collect::<HashSet<&str>>()
        .len()
}

/// The report for one fired cluster. `members` are indices into `hits` in time order.
fn make_hit(
    ci: usize,
    key: &[String],
    members: &[usize],
    hits: &[BaseHit],
) -> Option<CorrelationHit> {
    let first = hits.get(*members.first()?)?;
    let last = hits.get(*members.last()?)?;
    let hostname = members
        .iter()
        .all(|&m| hits[m].hostname == first.hostname)
        .then(|| first.hostname.clone())
        .flatten();
    Some(CorrelationHit {
        correlation_index: ci,
        timestamp: last.timestamp,
        first: first.timestamp,
        last: last.timestamp,
        count: members.len(),
        group_values: key.to_vec(),
        members: members.to_vec(),
        hostname,
    })
}

/// What the current window contains: the positions (into the sorted group) of its hits per base
/// rule, oldest first, and how often each `value_field` value occurs in it.
#[derive(Default)]
struct WindowState<'a> {
    positions: HashMap<usize, VecDeque<usize>>,
    values: HashMap<&'a str, usize>,
}

impl<'a> WindowState<'a> {
    fn add(&mut self, pos: usize, hit: &'a BaseHit) {
        self.positions
            .entry(hit.base_index)
            .or_default()
            .push_back(pos);
        if let Some(v) = hit.value_field.as_deref() {
            *self.values.entry(v).or_default() += 1;
        }
    }

    fn remove(&mut self, pos: usize, hit: &BaseHit) {
        if let Some(queue) = self.positions.get_mut(&hit.base_index) {
            if queue.front() == Some(&pos) {
                queue.pop_front();
            } else {
                queue.retain(|p| *p != pos);
            }
            if queue.is_empty() {
                self.positions.remove(&hit.base_index);
            }
        }
        if let Some(v) = hit.value_field.as_deref()
            && let Some(n) = self.values.get_mut(v)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.values.remove(v);
            }
        }
    }

    fn clear(&mut self) {
        self.positions.clear();
        self.values.clear();
    }

    /// Whether the window (holding `len` hits) satisfies the correlation.
    fn fires(&self, plan: &Plan, len: usize) -> bool {
        match plan.kind {
            CorrelationType::EventCount => plan.condition.matches(len as u64),
            CorrelationType::ValueCount => plan.condition.matches(self.values.len() as u64),
            CorrelationType::Temporal => self.has_all(&plan.required),
            CorrelationType::TemporalOrdered => self.in_order(&plan.required),
        }
    }

    fn has_all(&self, required: &[usize]) -> bool {
        required
            .iter()
            .all(|r| self.positions.get(r).is_some_and(|q| !q.is_empty()))
    }

    /// Every required base rule is present and their first occurrences follow `required`'s order.
    fn in_order(&self, required: &[usize]) -> bool {
        let mut previous: Option<usize> = None;
        for r in required {
            let Some(&first) = self.positions.get(r).and_then(VecDeque::front) else {
                return false;
            };
            if previous.is_some_and(|p| first <= p) {
                return false;
            }
            previous = Some(first);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::FieldValue;
    use crate::logsource::{LogSourceSpec, LogSourceTag};
    use crate::rules::{BaseRule, RuleMeta};
    use sigma_rust::{CorrelationEngine, SigmaCorrelationRule};

    // ----- fixtures ---------------------------------------------------------------------------

    /// The shipped PHP2Shell chain (keywords already wrapped in `*`, which the rule loader does).
    const PHP2SHELL_TEMPORAL: &str = "
title: PHP2Shell Exploitation Chain (Memory Pressure, Memory Disclosure, Worker Crash)
correlation:
    type: temporal
    rules:
        - php2shell_chain_pre_script_oom
        - php2shell_chain_session_id_too_long
        - php2shell_chain_apache_worker_crash
    timespan: 5m
level: critical
";
    const PHP2SHELL_ORDERED: &str = "
title: PHP2Shell Exploitation Chain (ordered)
correlation:
    type: temporal_ordered
    rules:
        - php2shell_chain_pre_script_oom
        - php2shell_chain_session_id_too_long
        - php2shell_chain_apache_worker_crash
    timespan: 5m
level: critical
";
    const BASE_OOM: &str = "
title: PHP2Shell Chain - Pre-Script Memory Exhaustion
name: php2shell_chain_pre_script_oom
logsource:
    product: php
    service: error_log
detection:
    keywords:
        - '*Allowed memory size of * exhausted * in Unknown on line 0*'
    condition: keywords
level: high
";
    const BASE_SESSION: &str = "
title: PHP2Shell Chain - Session ID Too Long
name: php2shell_chain_session_id_too_long
logsource:
    product: php
    service: error_log
detection:
    keywords:
        - '*Session ID is too long or contains illegal characters*'
    condition: keywords
level: high
";
    const BASE_CRASH: &str = "
title: PHP2Shell Chain - Apache Worker Crash
name: php2shell_chain_apache_worker_crash
logsource:
    service: apache
detection:
    keywords:
        - '*exit signal Segmentation fault*'
        - '*exit signal Abort*'
    condition: keywords
level: high
";
    const PHP2SHELL_BASES: &[&str] = &[BASE_OOM, BASE_SESSION, BASE_CRASH];

    /// The shipped rapid-POST rule.
    const RAPID_POSTS: &str = "
title: Rapid Repeated POST Requests To PHP Index Page
correlation:
    type: event_count
    rules:
        - post_to_php_index
    group-by:
        - c-ip
    timespan: 60s
    condition:
        gte: 3
level: medium
";
    const BASE_POST: &str = "
title: POST Request To Web Root Or PHP Index
name: post_to_php_index
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem:
            - '/'
            - '/index.php'
    condition: selection
level: informational
";

    const OOM_MSG: &str = "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0";
    const SESSION_MSG: &str = "PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, \"-\", and \",\" characters are allowed in Unknown on line 0";
    const CRASH_MSG: &str = "AH00051: child pid 31 exit signal Segmentation fault (11), possible coredump in /etc/apache2";

    // ----- helpers ----------------------------------------------------------------------------

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("test timestamp")
            .with_timezone(&Utc)
    }

    fn rfc(t: &DateTime<Utc>) -> String {
        t.to_rfc3339()
    }

    /// Build a `CorrelationRule` from the YAML documents of a correlation file, the way the rule
    /// loader does: `from_value::<SigmaCorrelationRule>` for the correlation, `rule_from_yaml`
    /// for the base rules, `rules:` entries resolved by `name`, then `id`, then `title`.
    fn correlation(corr_yaml: &str, bases: &[&str]) -> CorrelationRule {
        let value: yaml_serde::Value = yaml_serde::from_str(corr_yaml).expect("correlation yaml");
        let spec: SigmaCorrelationRule = yaml_serde::from_value(value).expect("correlation rule");
        let base_rules: Vec<BaseRule> = bases
            .iter()
            .map(|yaml| {
                let value: yaml_serde::Value = yaml_serde::from_str(yaml).expect("base yaml");
                let text = |key: &str| value.get(key).and_then(|v| v.as_str()).map(str::to_string);
                let name = text("name")
                    .or_else(|| text("id"))
                    .or_else(|| text("title"))
                    .expect("base rule name");
                let rule = sigma_rust::rule_from_yaml(yaml).expect("base rule");
                let mut identifiers = vec![name.clone()];
                for id in [text("id"), text("title")].into_iter().flatten() {
                    if !identifiers.contains(&id) {
                        identifiers.push(id);
                    }
                }
                BaseRule {
                    meta: RuleMeta {
                        title: text("title").unwrap_or_else(|| name.clone()),
                        ..Default::default()
                    },
                    logsource: LogSourceSpec::from_rule(&rule),
                    identifiers,
                    rule,
                }
            })
            .collect();
        let rule_order = spec
            .correlation
            .rules
            .iter()
            .map(|r| {
                base_rules
                    .iter()
                    .position(|b| b.identifiers.contains(r))
                    .expect("rules: entry resolves")
            })
            .collect();
        CorrelationRule {
            meta: RuleMeta {
                title: spec.title.clone(),
                level: spec.level.clone().unwrap_or_default(),
                rule_file: "test.yml".to_string(),
                ..Default::default()
            },
            condition_neq: value_neq(corr_yaml),
            spec,
            base_rules,
            rule_order,
        }
    }

    /// `correlation.condition.neq` of a test correlation, read like the rule loader does.
    fn value_neq(corr_yaml: &str) -> Option<u64> {
        let value: yaml_serde::Value = yaml_serde::from_str(corr_yaml).ok()?;
        value
            .get("correlation")?
            .get("condition")?
            .get("neq")?
            .as_u64()
    }

    fn parsed(fields: &[(&str, FieldValue)], host: Option<&str>) -> ParsedEvent {
        let raw = fields
            .iter()
            .find(|(k, _)| *k == "message")
            .map(|(_, v)| v.render())
            .unwrap_or_default();
        let mut ev = ParsedEvent::new(&raw, &LogSourceTag::WEBSERVER);
        for (k, v) in fields {
            ev.push(k, v.clone());
        }
        ev.hostname = host.map(str::to_string);
        ev
    }

    /// A base hit built through `make_base_hit` from a synthetic event.
    fn hit(
        corr: &CorrelationRule,
        ci: usize,
        bi: usize,
        when: &str,
        fields: &[(&str, FieldValue)],
        host: Option<&str>,
    ) -> BaseHit {
        let ev = parsed(fields, host);
        let sigma = ev.to_sigma_event();
        make_base_hit(
            corr,
            ci,
            bi,
            &sigma,
            &ev,
            ts(when),
            format!("{bi} (test.log:1)"),
        )
    }

    /// A hit of the PHP2Shell chain whose message really matches the base rule.
    fn php2shell_hit(corr: &CorrelationRule, bi: usize, when: &str) -> BaseHit {
        let msg = match bi {
            0 => OOM_MSG,
            1 => SESSION_MSG,
            _ => CRASH_MSG,
        };
        let ev = parsed(&[("message", msg.into())], Some("honeypot"));
        let sigma = ev.to_sigma_event();
        assert!(
            corr.base_rules[bi].rule.is_match(&sigma),
            "fixture message must match base rule {bi}"
        );
        let summary = format!(
            "{} (php-error.log:{})",
            corr.base_rules[bi].meta.title,
            bi + 1
        );
        make_base_hit(corr, 0, bi, &sigma, &ev, ts(when), summary)
    }

    fn post_hit(corr: &CorrelationRule, when: &str, ip: &str) -> BaseHit {
        hit(
            corr,
            0,
            0,
            when,
            &[
                ("c-ip", ip.into()),
                ("cs-method", "POST".into()),
                ("cs-uri-stem", "/index.php".into()),
                ("sc-status", 200i64.into()),
            ],
            Some("web01"),
        )
    }

    fn run(
        correlations: &[CorrelationRule],
        hits: &[BaseHit],
    ) -> (CorrelationOutcome, Vec<String>) {
        let mut warnings = Vec::new();
        let outcome = evaluate_with(correlations, hits, &mut |m| warnings.push(m));
        (outcome, warnings)
    }

    // ----- make_base_hit ----------------------------------------------------------------------

    #[test]
    fn make_base_hit_collects_group_values_value_field_and_hostname() {
        let corr = correlation(
            "
title: t
correlation:
    type: value_count
    rules: [post_to_php_index]
    group-by: [c-ip, sc-status]
    timespan: 60s
    condition:
        field: cs-username
        gte: 3
",
            &[BASE_POST],
        );
        let h = hit(
            &corr,
            3,
            0,
            "2026-10-24T15:35:31Z",
            &[
                ("c-ip", "203.0.113.5".into()),
                ("sc-status", 200i64.into()),
                ("cs-username", "alice".into()),
            ],
            Some("web01"),
        );
        assert_eq!(h.correlation_index, 3);
        assert_eq!(h.base_index, 0);
        assert_eq!(rfc(&h.timestamp), "2026-10-24T15:35:31+00:00");
        assert_eq!(
            h.group_values,
            Some(vec!["203.0.113.5".to_string(), "200".to_string()])
        );
        assert_eq!(h.value_field, Some("alice".to_string()));
        assert_eq!(h.hostname, Some("web01".to_string()));
        assert_eq!(h.summary, "0 (test.log:1)");
    }

    #[test]
    fn make_base_hit_treats_missing_and_null_group_by_fields_alike() {
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let missing = hit(
            &corr,
            0,
            0,
            "2026-10-24T15:35:31Z",
            &[("cs-method", "POST".into())],
            None,
        );
        assert_eq!(missing.group_values, None);
        assert_eq!(missing.value_field, None);
        assert_eq!(missing.hostname, None);
        let null = hit(
            &corr,
            0,
            0,
            "2026-10-24T15:35:31Z",
            &[("c-ip", FieldValue::Null)],
            None,
        );
        // A null value (CLF `-`) is no value: the hit is dropped like one without the field,
        // instead of merging every client without an address into one group.
        assert_eq!(null.group_values, None);
        // No group-by at all: every hit lands in the single empty group.
        let chain = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        assert_eq!(
            php2shell_hit(&chain, 0, "2026-10-24T15:35:33Z").group_values,
            Some(vec![])
        );
    }

    #[test]
    fn make_base_hit_resolves_aliases_per_base_rule() {
        let corr = correlation(
            "
title: alias
correlation:
    type: temporal
    rules: [login_failed, su_used]
    group-by: [user]
    timespan: 10m
    aliases:
        user:
            login_failed: cs-username
            su_used: username
",
            &[
                "title: A\nname: login_failed\nlogsource: {category: webserver}\ndetection:\n  sel:\n    sc-status: 401\n  condition: sel\n",
                "title: B\nname: su_used\nlogsource: {product: linux}\ndetection:\n  sel:\n    process: su\n  condition: sel\n",
            ],
        );
        let a = hit(
            &corr,
            0,
            0,
            "2026-10-24T15:35:31Z",
            &[("cs-username", "alice".into())],
            None,
        );
        let b = hit(
            &corr,
            0,
            1,
            "2026-10-24T15:35:40Z",
            &[("username", "alice".into())],
            None,
        );
        assert_eq!(a.group_values, Some(vec!["alice".to_string()]));
        assert_eq!(b.group_values, Some(vec!["alice".to_string()]));
        // The alias of the *other* rule does not apply: rule B has no `cs-username`.
        let wrong = hit(
            &corr,
            0,
            1,
            "2026-10-24T15:35:40Z",
            &[("cs-username", "alice".into())],
            None,
        );
        assert_eq!(wrong.group_values, None);
        // A base index the correlation does not have never panics; aliases simply do not apply.
        let stray = hit(
            &corr,
            0,
            9,
            "2026-10-24T15:35:40Z",
            &[("user", "alice".into())],
            None,
        );
        assert_eq!(stray.group_values, Some(vec!["alice".to_string()]));
    }

    // ----- temporal ---------------------------------------------------------------------------

    #[test]
    fn honeypot_chain_fires_one_temporal_hit() {
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(outcome.skipped_missing_group_by, 0);
        assert_eq!(outcome.hits.len(), 1);
        let h = &outcome.hits[0];
        assert_eq!(h.correlation_index, 0);
        assert_eq!(rfc(&h.timestamp), "2026-10-24T15:35:39+00:00");
        assert_eq!(rfc(&h.first), "2026-10-24T15:35:33+00:00");
        assert_eq!(rfc(&h.last), "2026-10-24T15:35:39+00:00");
        assert_eq!(h.count, 3);
        assert_eq!(h.members, vec![0, 1, 2]);
        assert!(h.group_values.is_empty());
        assert_eq!(h.hostname, Some("honeypot".to_string()));
    }

    #[test]
    fn chain_straddling_a_five_minute_boundary_still_fires() {
        // Case B15: fixed 5-minute buckets put 17:34:43/17:34:45 and 17:35:01 in different buckets.
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let hits = vec![
            php2shell_hit(&corr, 2, "2026-10-24T17:34:43Z"),
            php2shell_hit(&corr, 0, "2026-10-24T17:34:45Z"),
            php2shell_hit(&corr, 1, "2026-10-24T17:35:01Z"),
        ];
        assert_ne!(
            bucket_key(hits[0].timestamp, 300),
            bucket_key(hits[2].timestamp, 300),
            "the chain must really cross a bucket boundary"
        );
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        let h = &outcome.hits[0];
        assert_eq!(rfc(&h.timestamp), "2026-10-24T17:35:01+00:00");
        assert_eq!(rfc(&h.first), "2026-10-24T17:34:43+00:00");
        assert_eq!(h.count, 3);
        assert_eq!(h.members, vec![0, 1, 2]);
    }

    #[test]
    fn chain_missing_a_base_rule_does_not_fire() {
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 0, "2026-10-24T15:35:38Z"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert!(outcome.hits.is_empty());
        // ... and a crash more than 5 minutes after the OOM does not complete it either.
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:40:34Z"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert!(outcome.hits.is_empty());
    }

    #[test]
    fn temporal_window_end_is_inclusive_and_sorts_unordered_input() {
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        // Arrives crash-first (two files scanned in parallel); exactly 5 minutes apart.
        let hits = vec![
            php2shell_hit(&corr, 2, "2026-10-24T15:40:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![2, 1, 0]);
        assert_eq!(rfc(&outcome.hits[0].timestamp), "2026-10-24T15:40:33+00:00");
    }

    #[test]
    fn two_chains_inside_one_window_are_one_report_and_separate_chains_two() {
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
            // a second chain two minutes later: inside the first window, merged into one report
            php2shell_hit(&corr, 0, "2026-10-24T15:37:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:37:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:37:39Z"),
            // a third chain an hour later: its own report
            php2shell_hit(&corr, 0, "2026-10-24T16:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T16:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T16:35:39Z"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 2);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(outcome.hits[0].count, 6);
        assert_eq!(rfc(&outcome.hits[0].timestamp), "2026-10-24T15:37:39+00:00");
        assert_eq!(outcome.hits[1].members, vec![6, 7, 8]);
        assert_eq!(rfc(&outcome.hits[1].timestamp), "2026-10-24T16:35:39+00:00");
    }

    #[test]
    fn temporal_ordered_respects_the_rule_order() {
        let corr = correlation(PHP2SHELL_ORDERED, PHP2SHELL_BASES);
        let in_order = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
        ];
        let (outcome, _) = run(&[corr], &in_order);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2]);
        assert_eq!(rfc(&outcome.hits[0].timestamp), "2026-10-24T15:35:39+00:00");

        // Session before OOM: every window that holds all three has them out of order.
        let corr = correlation(PHP2SHELL_ORDERED, PHP2SHELL_BASES);
        let out_of_order = vec![
            php2shell_hit(&corr, 1, "2026-10-24T15:35:30Z"),
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:41Z"),
        ];
        let (outcome, _) = run(&[corr], &out_of_order);
        assert!(outcome.hits.is_empty());

        // The plain temporal rule accepts the same hits.
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let (outcome, _) = run(&[corr], &out_of_order);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2, 3]);
    }

    #[test]
    fn temporal_ordered_only_checks_first_occurrences() {
        // OOM, session, OOM again, crash: the first occurrences are in order.
        let corr = correlation(PHP2SHELL_ORDERED, PHP2SHELL_BASES);
        let hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 0, "2026-10-24T15:35:37Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2, 3]);
        assert_eq!(outcome.hits[0].count, 4);
    }

    // ----- event_count ------------------------------------------------------------------------

    #[test]
    fn four_rapid_posts_fire_once_and_two_posts_from_another_ip_do_not() {
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:32Z", "198.51.100.7"),
            post_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:34Z", "198.51.100.7"),
            post_hit(&corr, "2026-10-24T15:35:35Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:37Z", "203.0.113.5"),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(outcome.hits.len(), 1, "one cluster, not one hit per window");
        let h = &outcome.hits[0];
        assert_eq!(h.group_values, vec!["203.0.113.5".to_string()]);
        assert_eq!(h.members, vec![0, 2, 4, 5]);
        assert_eq!(h.count, 4);
        assert_eq!(rfc(&h.first), "2026-10-24T15:35:31+00:00");
        assert_eq!(rfc(&h.last), "2026-10-24T15:35:37+00:00");
        assert_eq!(rfc(&h.timestamp), "2026-10-24T15:35:37+00:00");
        assert_eq!(h.hostname, Some("web01".to_string()));
    }

    #[test]
    fn posts_crossing_a_minute_boundary_fire() {
        // Fixed 60-second buckets would see 2 + 2.
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:57Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:59Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:36:01Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:36:03Z", "203.0.113.5"),
        ];
        assert_ne!(
            bucket_key(hits[1].timestamp, 60),
            bucket_key(hits[2].timestamp, 60)
        );
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2, 3]);
        assert_eq!(rfc(&outcome.hits[0].timestamp), "2026-10-24T15:36:03+00:00");
    }

    #[test]
    fn a_second_burst_after_the_window_is_a_second_report() {
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:35Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:37Z", "203.0.113.5"),
            // 15:36:31 is exactly 60 s after the first hit: still inside the first window
            post_hit(&corr, "2026-10-24T15:36:31Z", "203.0.113.5"),
            // the next burst starts after the window
            post_hit(&corr, "2026-10-24T15:38:00Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:38:10Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:38:20Z", "203.0.113.5"),
            // a lonely one at the end
            post_hit(&corr, "2026-10-24T15:45:00Z", "203.0.113.5"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 2);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2, 3, 4]);
        assert_eq!(outcome.hits[1].members, vec![5, 6, 7]);
    }

    #[test]
    fn two_groups_are_independent() {
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:32Z", "198.51.100.7"),
            post_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:34Z", "198.51.100.7"),
            post_hit(&corr, "2026-10-24T15:35:36Z", "198.51.100.7"),
            post_hit(&corr, "2026-10-24T15:35:35Z", "203.0.113.5"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 2);
        // sorted by timestamp: the 203.0.113.5 cluster ends at :35, the other at :36
        assert_eq!(
            outcome.hits[0].group_values,
            vec!["203.0.113.5".to_string()]
        );
        assert_eq!(outcome.hits[0].members, vec![0, 2, 5]);
        assert_eq!(rfc(&outcome.hits[0].timestamp), "2026-10-24T15:35:35+00:00");
        assert_eq!(
            outcome.hits[1].group_values,
            vec!["198.51.100.7".to_string()]
        );
        assert_eq!(outcome.hits[1].members, vec![1, 3, 4]);
        assert_eq!(rfc(&outcome.hits[1].timestamp), "2026-10-24T15:35:36+00:00");
    }

    #[test]
    fn hits_lacking_the_group_by_field_are_counted_and_do_not_abort() {
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let no_ip = |when: &str| hit(&corr, 0, 0, when, &[("cs-method", "POST".into())], None);
        let hits = vec![
            no_ip("2026-10-24T15:35:30Z"),
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5"),
            no_ip("2026-10-24T15:35:34Z"),
            post_hit(&corr, "2026-10-24T15:35:35Z", "203.0.113.5"),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty());
        assert_eq!(outcome.skipped_missing_group_by, 2);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![1, 2, 4]);
    }

    #[test]
    fn eq_uses_fixed_buckets_and_gt_the_sliding_window() {
        let eq = correlation(
            "title: eq\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    eq: 2\n",
            &[BASE_POST],
        );
        let hits = vec![
            post_hit(&eq, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&eq, "2026-10-24T15:35:33Z", "203.0.113.5"),
            post_hit(&eq, "2026-10-24T15:35:35Z", "203.0.113.5"),
        ];
        let (outcome, _) = run(std::slice::from_ref(&eq), &hits);
        // A sliding window can always be shrunk to "exactly 2", so `eq` is judged on the fixed
        // 60 s bucket, which holds 3 hits: no report.
        assert!(outcome.hits.is_empty());
        let two = vec![
            post_hit(&eq, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&eq, "2026-10-24T15:35:33Z", "203.0.113.5"),
            post_hit(&eq, "2026-10-24T15:36:05Z", "203.0.113.5"),
        ];
        let (outcome, _) = run(&[eq], &two);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1]);

        let gt = correlation(
            "title: gt\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    gt: 2\n",
            &[BASE_POST],
        );
        let (outcome, _) = run(&[gt], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2]);
        let gt3 = correlation(
            "title: gt\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    gt: 3\n",
            &[BASE_POST],
        );
        let (outcome, _) = run(&[gt3], &hits);
        assert!(outcome.hits.is_empty());
    }

    #[test]
    fn lt_condition_uses_fixed_buckets() {
        let corr = correlation(
            "title: lt\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    lt: 3\n",
            &[BASE_POST],
        );
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:58Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:59Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:36:00Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:36:01Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:36:02Z", "203.0.113.5"),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty());
        // Bucket 15:35 holds 2 (< 3), bucket 15:36 holds 3. A sliding window would have reported
        // the lonely trailing hits instead.
        assert_eq!(outcome.hits.len(), 1);
        let h = &outcome.hits[0];
        assert_eq!(h.members, vec![0, 1]);
        assert_eq!(h.count, 2);
        assert_eq!(rfc(&h.first), "2026-10-24T15:35:58+00:00");
        assert_eq!(rfc(&h.timestamp), "2026-10-24T15:35:59+00:00");

        // `gte` + `lte` together is a fixed-bucket condition too: 15:36 (3 hits) is in [3, 4].
        let corr = correlation(
            "title: range\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    gte: 3\n    lte: 4\n",
            &[BASE_POST],
        );
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![2, 3, 4]);
    }

    #[test]
    fn zero_timespan_means_the_same_instant() {
        let corr = correlation(
            "title: zero\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 0s\n  condition:\n    gte: 2\n",
            &[BASE_POST],
        );
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:32Z", "203.0.113.5"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1]);
        // fixed buckets of width 0 are single instants as well
        let corr = correlation(
            "title: zero\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 0s\n  condition:\n    lt: 2\n",
            &[BASE_POST],
        );
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![2]);
    }

    #[test]
    fn missing_condition_is_gte_one_with_one_warning() {
        let corr = correlation(
            "title: nocond\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n",
            &[BASE_POST],
        );
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:32Z", "198.51.100.7"),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("nocond") && warnings[0].contains("gte: 1"));
        assert_eq!(outcome.hits.len(), 2);
        assert_eq!(outcome.hits[0].members, vec![2]);
        assert_eq!(outcome.hits[1].members, vec![0, 1]);
    }

    // ----- value_count ------------------------------------------------------------------------

    const DISTINCT_USERS: &str = "
title: Three Users From One Client
correlation:
    type: value_count
    rules: [post_to_php_index]
    group-by: [c-ip]
    timespan: 60s
    condition:
        field: cs-username
        gte: 3
";

    fn user_hit(corr: &CorrelationRule, when: &str, ip: &str, user: Option<&str>) -> BaseHit {
        let mut fields: Vec<(&str, FieldValue)> = vec![("c-ip", ip.into())];
        if let Some(u) = user {
            fields.push(("cs-username", u.into()));
        }
        hit(corr, 0, 0, when, &fields, Some("web01"))
    }

    #[test]
    fn value_count_counts_distinct_values_in_the_window() {
        let corr = correlation(DISTINCT_USERS, &[BASE_POST]);
        let hits = vec![
            user_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5", Some("alice")),
            user_hit(&corr, "2026-10-24T15:35:32Z", "203.0.113.5", Some("bob")),
            user_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5", None),
            user_hit(&corr, "2026-10-24T15:35:34Z", "203.0.113.5", Some("carol")),
            // another client repeats two users four times: never 3 distinct
            user_hit(&corr, "2026-10-24T15:35:31Z", "198.51.100.7", Some("alice")),
            user_hit(&corr, "2026-10-24T15:35:32Z", "198.51.100.7", Some("bob")),
            user_hit(&corr, "2026-10-24T15:35:33Z", "198.51.100.7", Some("alice")),
            user_hit(&corr, "2026-10-24T15:35:34Z", "198.51.100.7", Some("bob")),
        ];
        assert_eq!(hits[2].value_field, None);
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty());
        assert_eq!(outcome.hits.len(), 1);
        let h = &outcome.hits[0];
        assert_eq!(h.group_values, vec!["203.0.113.5".to_string()]);
        // the hit without a user name is a member of the window, it just adds no value
        assert_eq!(h.members, vec![0, 1, 2, 3]);
        assert_eq!(h.count, 4);
        assert_eq!(rfc(&h.timestamp), "2026-10-24T15:35:34+00:00");
    }

    #[test]
    fn value_count_slides_across_boundaries_and_lt_uses_buckets() {
        let corr = correlation(DISTINCT_USERS, &[BASE_POST]);
        let hits = vec![
            user_hit(&corr, "2026-10-24T15:35:58Z", "203.0.113.5", Some("alice")),
            user_hit(&corr, "2026-10-24T15:35:59Z", "203.0.113.5", Some("alice")),
            user_hit(&corr, "2026-10-24T15:36:00Z", "203.0.113.5", Some("bob")),
            user_hit(&corr, "2026-10-24T15:36:01Z", "203.0.113.5", Some("carol")),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1, 2, 3]);

        let corr = correlation(
            "title: few\ncorrelation:\n  type: value_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    field: cs-username\n    lte: 1\n",
            &[BASE_POST],
        );
        let (outcome, _) = run(&[corr], &hits);
        // bucket 15:35 has one distinct user (alice twice), bucket 15:36 has two
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1]);
    }

    #[test]
    fn value_count_without_a_field_is_skipped_with_a_warning() {
        let corr = correlation(
            "title: nofield\ncorrelation:\n  type: value_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    gte: 1\n",
            &[BASE_POST],
        );
        let hits = vec![post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5")];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(outcome.hits.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("nofield") && warnings[0].contains("field"));
    }

    // ----- aliases, hostnames, ordering, robustness -----------------------------------------

    #[test]
    fn aliases_resolve_a_differently_named_field_for_one_base_rule() {
        let yaml = "
title: Failed Web Login Then su
correlation:
    type: temporal
    rules: [login_failed, su_used]
    group-by: [user]
    timespan: 10m
    aliases:
        user:
            login_failed: cs-username
            su_used: username
";
        let bases = [
            "title: Failed Login\nname: login_failed\nlogsource: {category: webserver}\ndetection:\n  sel:\n    sc-status: 401\n  condition: sel\n",
            "title: su\nname: su_used\nlogsource: {product: linux}\ndetection:\n  sel:\n    process: su\n  condition: sel\n",
        ];
        let corr = correlation(yaml, &bases);
        let hits = vec![
            hit(
                &corr,
                0,
                0,
                "2026-10-24T15:35:31Z",
                &[("cs-username", "alice".into())],
                Some("web01"),
            ),
            hit(
                &corr,
                0,
                1,
                "2026-10-24T15:36:00Z",
                &[("username", "alice".into())],
                Some("web01"),
            ),
            hit(
                &corr,
                0,
                0,
                "2026-10-24T15:37:00Z",
                &[("cs-username", "bob".into())],
                Some("web01"),
            ),
            hit(
                &corr,
                0,
                1,
                "2026-10-24T15:38:00Z",
                &[("username", "carol".into())],
                Some("web01"),
            ),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty());
        assert_eq!(outcome.skipped_missing_group_by, 0);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].group_values, vec!["alice".to_string()]);
        assert_eq!(outcome.hits[0].members, vec![0, 1]);
    }

    #[test]
    fn hostname_is_reported_only_when_the_members_agree() {
        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let mut hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
        ];
        hits[2].hostname = Some("other".to_string());
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].hostname, None);

        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        hits[2].hostname = None;
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits[0].hostname, None);

        let corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        for h in &mut hits {
            h.hostname = None;
        }
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits[0].hostname, None);
    }

    #[test]
    fn hits_of_several_correlations_are_sorted_by_timestamp() {
        let chain = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        let posts = correlation(RAPID_POSTS, &[BASE_POST]);
        let mut hits = vec![
            php2shell_hit(&chain, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&chain, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&chain, 2, "2026-10-24T15:35:39Z"),
        ];
        for when in [
            "2026-10-24T15:35:21Z",
            "2026-10-24T15:35:23Z",
            "2026-10-24T15:35:25Z",
        ] {
            let mut h = post_hit(&posts, when, "203.0.113.5");
            h.correlation_index = 1;
            hits.push(h);
        }
        // a hit for a correlation that does not exist is ignored, never a panic
        let mut stray = post_hit(&posts, "2026-10-24T15:35:00Z", "203.0.113.5");
        stray.correlation_index = 7;
        hits.push(stray);
        let (outcome, warnings) = run(&[chain, posts], &hits);
        assert!(warnings.is_empty());
        assert_eq!(outcome.hits.len(), 2);
        assert_eq!(outcome.hits[0].correlation_index, 1);
        assert_eq!(rfc(&outcome.hits[0].timestamp), "2026-10-24T15:35:25+00:00");
        assert_eq!(outcome.hits[0].members, vec![3, 4, 5]);
        assert_eq!(outcome.hits[1].correlation_index, 0);
        assert_eq!(rfc(&outcome.hits[1].timestamp), "2026-10-24T15:35:39+00:00");
        assert_eq!(outcome.hits[1].members, vec![0, 1, 2]);
    }

    #[test]
    fn empty_inputs_give_an_empty_outcome() {
        let (outcome, warnings) = run(&[], &[]);
        assert!(outcome.hits.is_empty() && warnings.is_empty());
        assert_eq!(outcome.skipped_missing_group_by, 0);
        let corr = correlation(RAPID_POSTS, &[BASE_POST]);
        let (outcome, warnings) = run(&[corr], &[]);
        assert!(outcome.hits.is_empty() && warnings.is_empty());
        let posts = correlation(RAPID_POSTS, &[BASE_POST]);
        let hits = vec![post_hit(&posts, "2026-10-24T15:35:31Z", "203.0.113.5")];
        let (outcome, _) = run(&[], &hits);
        assert!(outcome.hits.is_empty());
    }

    #[test]
    fn invalid_or_absurd_timespan_skips_the_rule_with_a_warning() {
        for span in ["5 minutes", "", "99999999999999999999d", "1.5m", "-5s"] {
            let corr = correlation(
                &format!(
                    "title: bad\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: '{span}'\n  condition:\n    gte: 1\n"
                ),
                &[BASE_POST],
            );
            let hits = vec![post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5")];
            let (outcome, warnings) = run(&[corr], &hits);
            assert!(outcome.hits.is_empty(), "timespan {span:?}");
            assert_eq!(warnings.len(), 1, "timespan {span:?}");
            assert!(warnings[0].contains("timespan"), "{}", warnings[0]);
        }
    }

    #[test]
    fn timespan_grammar_agrees_with_sigma_rust() {
        for text in [
            "60s", "5m", "2h", "1d", "0s", " 30s ", "+5m", "5min", "", "s", "abc", "-5s", "1.5m",
            "5 m", "1w",
        ] {
            let ours = timespan_seconds(text);
            let theirs = CorrelationEngine::parse_timespan(text)
                .ok()
                .map(|d| d.as_secs() as i64);
            assert_eq!(ours, theirs, "timespan {text:?}");
        }
        assert_eq!(timespan_seconds("5m"), Some(300));
        assert_eq!(timespan_seconds("99999999999999999999d"), None);
    }

    #[test]
    fn huge_timespan_does_not_overflow_the_window() {
        let corr = correlation(
            "title: huge\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 100000000000d\n  condition:\n    gte: 2\n",
            &[BASE_POST],
        );
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:33Z", "203.0.113.5"),
        ];
        let (outcome, warnings) = run(&[corr], &hits);
        assert!(warnings.is_empty());
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1]);
    }

    #[test]
    fn rule_order_quirks_never_panic() {
        // Duplicate entries are collapsed: OOM twice + crash still fires.
        let mut corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        corr.rule_order = vec![0, 0, 2];
        let hits = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].members, vec![0, 1]);

        // An index without a base rule can never be satisfied.
        let mut corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        corr.rule_order = vec![0, 2, 42];
        let (outcome, _) = run(&[corr], &hits);
        assert!(outcome.hits.is_empty());

        // An empty order falls back to every base rule of the file: two of three do not fire,
        // all three do.
        let mut corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        corr.rule_order = Vec::new();
        let (outcome, _) = run(&[corr], &hits);
        assert!(outcome.hits.is_empty());
        let mut corr = correlation(PHP2SHELL_TEMPORAL, PHP2SHELL_BASES);
        corr.rule_order = Vec::new();
        let all = vec![
            php2shell_hit(&corr, 0, "2026-10-24T15:35:33Z"),
            php2shell_hit(&corr, 1, "2026-10-24T15:35:36Z"),
            php2shell_hit(&corr, 2, "2026-10-24T15:35:39Z"),
        ];
        let (outcome, _) = run(&[corr], &all);
        assert_eq!(outcome.hits.len(), 1);
    }

    #[test]
    fn neq_is_evaluated_on_fixed_buckets() {
        let neq = correlation(
            "title: neq\ncorrelation:\n  type: event_count\n  rules: [post_to_php_index]\n  group-by: [c-ip]\n  timespan: 60s\n  condition:\n    neq: 1\n",
            &[BASE_POST],
        );
        assert_eq!(neq.condition_neq, Some(1));
        let hits = vec![
            post_hit(&neq, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&neq, "2026-10-24T15:35:31Z", "203.0.113.6"),
            post_hit(&neq, "2026-10-24T15:35:33Z", "203.0.113.6"),
        ];
        let (outcome, warnings) = run(&[neq], &hits);
        assert!(warnings.is_empty(), "{warnings:?}");
        // .5 has one hit (excluded by neq: 1), .6 has two.
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(
            outcome.hits[0].group_values,
            vec!["203.0.113.6".to_string()]
        );
    }

    #[test]
    fn aliases_may_key_the_base_rule_by_id() {
        let corr = correlation(
            "title: by id\ncorrelation:\n  type: event_count\n  rules: [base-post-id]\n  group-by: [client]\n  timespan: 60s\n  aliases:\n    client:\n      base-post-id: c-ip\n  condition:\n    gte: 2\n",
            &[
                "title: Base\nname: base_post\nid: base-post-id\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-method: POST\n  condition: sel\n",
            ],
        );
        let hits = vec![
            post_hit(&corr, "2026-10-24T15:35:31Z", "203.0.113.5"),
            post_hit(&corr, "2026-10-24T15:35:32Z", "203.0.113.5"),
        ];
        let (outcome, _) = run(&[corr], &hits);
        assert_eq!(outcome.skipped_missing_group_by, 0);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(
            outcome.hits[0].group_values,
            vec!["203.0.113.5".to_string()]
        );
    }

    #[test]
    fn same_second_hits_keep_their_log_order_for_temporal_ordered() {
        let bases = [
            "title: Get\nname: get\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-method: GET\n  condition: sel\n",
            "title: Post\nname: post\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-method: POST\n  condition: sel\n",
        ];
        let ordered = |rules: &str| {
            correlation(
                &format!(
                    "title: ordered\ncorrelation:\n  type: temporal_ordered\n  rules: [{rules}]\n  timespan: 60s\n"
                ),
                &bases,
            )
        };
        let at = |corr: &CorrelationRule, bi: usize, method: &str, line: usize| {
            let mut h = hit(
                corr,
                0,
                bi,
                "2026-10-24T15:35:31Z",
                &[("cs-method", method.into())],
                None,
            );
            h.file = Arc::from("access.log");
            h.line = line;
            h
        };
        // GET is logged on line 1, POST on line 2, in the same second.
        let get_then_post = ordered("get, post");
        let hits = vec![
            at(&get_then_post, 1, "POST", 2),
            at(&get_then_post, 0, "GET", 1),
        ];
        assert_eq!(run(&[get_then_post], &hits).0.hits.len(), 1);
        let post_then_get = ordered("post, get");
        let hits = vec![
            at(&post_then_get, 1, "POST", 2),
            at(&post_then_get, 0, "GET", 1),
        ];
        assert!(run(&[post_then_get], &hits).0.hits.is_empty());
    }
}
