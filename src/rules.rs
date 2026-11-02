//! Rule loading: YAML documents → sigma-rust rules, with keyword normalization (design §6,
//! amendment A11), correlation files (A12/A13), filtering and load statistics.
//!
//! Every `*.yml`/`*.yaml` file under the rule path is read and split into YAML documents. A file
//! is a *correlation file* when one of its documents has a `correlation` key; such a file is
//! loaded as a whole or not at all, and its base rules are only reported through their
//! correlation. Every other document is a detection rule. Before a document is handed to
//! sigma-rust its `detection` section is rewritten by [`normalize_detection`] so that keyword
//! lists match anywhere in the log line, as the Sigma specification requires.

use crate::errorlog::{log_error, log_warn};
use crate::logsource::LogSourceSpec;
use serde::Deserialize;
use sigma_rust::{Rule, SigmaCorrelationRule};
use std::fs;
use std::path::{Path, PathBuf};
use yaml_serde::{Mapping, Value};

/// Rule metadata rendered by the output, shared by detection and correlation rules.
#[derive(Clone, Debug, Default)]
pub struct RuleMeta {
    pub title: String,
    pub id: Option<String>,
    /// Lowercase Sigma level (`informational` when the rule has none).
    pub level: String,
    /// Lowercase status, if any.
    pub status: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    /// File name of the rule (without directories).
    pub rule_file: String,
}

/// A detection rule ready to run.
pub struct LoadedRule {
    pub rule: Rule,
    pub meta: RuleMeta,
    pub logsource: LogSourceSpec,
}

/// A base rule of a correlation file (only reported through its correlation).
pub struct BaseRule {
    /// Every identifier the rule can be referenced by in `rules:` and keyed by in `aliases:`:
    /// `name` (or, without one, `id`, then `title`) first, then `id` and `title`. The `rules:`
    /// entry that referenced it is always one of them.
    pub identifiers: Vec<String>,
    pub rule: Rule,
    pub meta: RuleMeta,
    pub logsource: LogSourceSpec,
}

#[cfg(test)]
impl BaseRule {
    /// The identifier a correlation references the rule by (`name`, else `id`, else `title`).
    pub fn name(&self) -> &str {
        self.identifiers.first().map(String::as_str).unwrap_or("")
    }
}

/// A correlation rule with its base rules.
pub struct CorrelationRule {
    pub spec: SigmaCorrelationRule,
    pub meta: RuleMeta,
    pub base_rules: Vec<BaseRule>,
    /// Indices into `base_rules`, in the order of the correlation's `rules:` list.
    pub rule_order: Vec<usize>,
    /// `condition: {neq: n}`. The Sigma correlation specification allows `neq`, but sigma-rust's
    /// `CorrelationCondition` has no such field, so it is read from the YAML by the loader.
    pub condition_neq: Option<u64>,
}

/// Which rules to keep (`-m`, `-D`, `-u`, `--include/exclude-status`, `--include/exclude-tag`).
#[derive(Clone, Debug, Default)]
pub struct RuleFilters {
    pub min_level: String,
    pub enable_deprecated: bool,
    pub enable_unsupported: bool,
    pub include_status: Vec<String>,
    pub exclude_status: Vec<String>,
    pub include_tag: Vec<String>,
    pub exclude_tag: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct LoadStats {
    pub files_seen: usize,
    pub loaded: usize,
    pub correlations: usize,
    pub skipped_unsupported_logsource: usize,
    pub skipped_status: usize,
    pub skipped_level: usize,
    pub skipped_tag: usize,
    pub failed: usize,
}

pub struct RuleSet {
    pub rules: Vec<LoadedRule>,
    pub correlations: Vec<CorrelationRule>,
    pub stats: LoadStats,
}

/// Modifiers that decide how a value is compared. A field-less selection key (`'|all'`) that has
/// none of these gets `contains` inserted when it is rewritten to `raw|...` (amendment A11).
const MATCH_MODIFIERS: &[&str] = &[
    "contains",
    "startswith",
    "endswith",
    "re",
    "cidr",
    "exists",
    "lt",
    "lte",
    "gt",
    "gte",
    "neq",
    "fieldref",
    "expand",
    "base64",
    "base64offset",
];

/// The Sigma rule statuses; a correlation rule's status string is validated against them (the
/// detection rule's is an enum in sigma-rust and validated there).
const VALID_STATUSES: &[&str] = &[
    "stable",
    "test",
    "experimental",
    "deprecated",
    "unsupported",
];

/// The field every event carries with the whole log line (`ParsedEvent::to_sigma_event`).
const RAW_FIELD: &str = "raw";

/// Upper bound on the YAML documents read from one file. The yaml_serde document iterator
/// yields the same failure forever once a document is broken, so the reading loop stops at the
/// first error and, as a second safety net, at this many documents.
const MAX_DOCUMENTS: usize = 1024;

/// Directory nesting accepted below the rule path (a symlink loop would otherwise never end).
const MAX_DEPTH: usize = 64;

/// Load every `*.yml`/`*.yaml` under `path` (or the single file) and apply the filters.
pub fn load_rules(path: &Path, filters: &RuleFilters) -> RuleSet {
    let mut set = RuleSet {
        rules: Vec::new(),
        correlations: Vec::new(),
        stats: LoadStats::default(),
    };
    let files = collect_rule_files(path);
    set.stats.files_seen = files.len();
    for file in &files {
        load_file(file, filters, &mut set);
    }
    set.stats.loaded = set.rules.len();
    set.stats.correlations = set.correlations.len();
    set
}

/// Rewrite a rule document so keyword selections match anywhere in the log message
/// (design §6 and amendment A11). Safe to call on correlation documents (no `detection`).
///
/// For every entry of `detection` except `condition`:
/// - a scalar becomes a one-element list, then
/// - a list of scalars has each entry wrapped in `*` wildcards unless it already starts with `*`
///   / ends with an unescaped `*` (a trailing odd run of backslashes gets one more backslash so
///   the appended `*` stays a wildcard); numbers and booleans become `*<text>*` strings;
/// - a mapping (or each mapping of a list of mappings) has every key with an empty field name
///   (`'|all'`, `'|contains|all'`, `'|re'`) rewritten to `raw|<modifiers>`, with `contains`
///   inserted when the chain has no match modifier. Keys with a real field name are untouched.
pub fn normalize_detection(doc: &mut Value) {
    let Some(detection) = doc.get_mut("detection").and_then(Value::as_mapping_mut) else {
        return;
    };
    for (key, value) in detection.iter_mut() {
        if key.as_str() == Some("condition") {
            continue;
        }
        normalize_selection(value);
    }
}

/// `informational`=1 .. `critical`=5, 0 for unknown text.
pub fn level_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "informational" | "info" => 1,
        "low" => 2,
        "medium" | "med" => 3,
        "high" => 4,
        "critical" | "crit" => 5,
        _ => 0,
    }
}

/// Canonical lowercase level name (`info` → `informational`, `crit` → `critical`).
pub fn canonical_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "info" | "informational" => "informational".to_string(),
        "med" | "medium" => "medium".to_string(),
        "crit" | "critical" => "critical".to_string(),
        other => other.to_string(),
    }
}

// --- file discovery -----------------------------------------------------------------------------

/// Every rule file under `path`, sorted so that rule indices are stable between runs.
fn collect_rule_files(path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if path.is_dir() {
        walk_dir(path, 0, &mut files);
    } else if path.is_file() {
        if is_rule_file(path) {
            files.push(path.to_path_buf());
        } else {
            log_warn(&format!(
                "Ignored {}: rule files must have the extension .yml or .yaml",
                path.display()
            ));
        }
    } else {
        log_error(&format!("Rule path {} does not exist", path.display()));
    }
    files
}

fn walk_dir(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        log_warn(&format!(
            "Rule directory {} is nested too deeply (more than {MAX_DEPTH} levels); not descended",
            dir.display()
        ));
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            log_warn(&format!(
                "Could not read the rule directory {}: {e}",
                dir.display()
            ));
            return;
        }
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            walk_dir(&p, depth + 1, files);
        } else if p.is_file() && is_rule_file(&p) {
            files.push(p);
        }
    }
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

// --- one file -------------------------------------------------------------------------------------

fn load_file(path: &Path, filters: &RuleFilters, set: &mut RuleSet) {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            log_error(&format!("Failed to read rule {}: {e}", path.display()));
            set.stats.failed += 1;
            return;
        }
    };
    let docs = match split_documents(&text) {
        Ok(docs) => docs,
        Err(e) => {
            log_error(&format!("Failed to parse rule {}: {e}", path.display()));
            set.stats.failed += 1;
            return;
        }
    };
    // `---` with nothing after it, or a file of comments only, yields null documents.
    let docs: Vec<Value> = docs.into_iter().filter(|d| !d.is_null()).collect();
    if docs.is_empty() {
        log_error(&format!(
            "Failed to parse rule {}: the file contains no YAML document",
            path.display()
        ));
        set.stats.failed += 1;
        return;
    }
    if docs.iter().any(is_correlation_doc) {
        load_correlation_file(path, docs, filters, set);
    } else {
        for doc in docs {
            load_detection_doc(path, doc, filters, set);
        }
    }
}

/// The YAML documents of a file, in order. Stops at the first broken document: the iterator
/// would otherwise repeat the failure endlessly.
fn split_documents(text: &str) -> Result<Vec<Value>, String> {
    let mut docs = Vec::new();
    for document in yaml_serde::Deserializer::from_str(text) {
        match Value::deserialize(document) {
            Ok(value) => docs.push(value),
            Err(e) => return Err(e.to_string()),
        }
        if docs.len() > MAX_DOCUMENTS {
            return Err(format!(
                "more than {MAX_DOCUMENTS} YAML documents in one file"
            ));
        }
    }
    Ok(docs)
}

fn is_correlation_doc(doc: &Value) -> bool {
    doc.get("correlation").is_some()
}

fn load_detection_doc(path: &Path, mut doc: Value, filters: &RuleFilters, set: &mut RuleSet) {
    if let Err(e) = check_condition_patterns(&doc) {
        log_error(&format!("Failed to parse rule {}: {e}", path.display()));
        set.stats.failed += 1;
        return;
    }
    normalize_detection(&mut doc);
    let rule: Rule = match yaml_serde::from_value(doc) {
        Ok(rule) => rule,
        Err(e) => {
            log_error(&format!("Failed to parse rule {}: {e}", path.display()));
            set.stats.failed += 1;
            return;
        }
    };
    let meta = meta_from_rule(&rule, path);
    let logsource = LogSourceSpec::from_rule(&rule);
    if !logsource.is_supported() {
        set.stats.skipped_unsupported_logsource += 1;
        log_warn(&format!(
            "Skipped rule with an unsupported log source ({logsource}): {} ({})",
            meta.title, meta.rule_file
        ));
        return;
    }
    if let Some(skip) = filter_reason(&meta, filters) {
        count_skip(&mut set.stats, skip);
        return;
    }
    set.rules.push(LoadedRule {
        rule,
        meta,
        logsource,
    });
}

// --- metadata -------------------------------------------------------------------------------------

fn meta_from_rule(rule: &Rule, path: &Path) -> RuleMeta {
    RuleMeta {
        title: rule.title.clone(),
        id: rule.id.clone(),
        level: rule
            .level
            .as_ref()
            .map(|l| canonical_level(&format!("{l:?}")))
            .unwrap_or_else(|| "informational".to_string()),
        status: rule
            .status
            .as_ref()
            .map(|s| format!("{s:?}").to_ascii_lowercase()),
        author: rule.author.clone(),
        date: rule.date.clone(),
        modified: rule.modified.clone(),
        description: rule.description.as_deref().map(trim_block),
        references: rule.references.clone().unwrap_or_default(),
        tags: rule.tags.clone().unwrap_or_default(),
        falsepositives: rule.falsepositives.clone().unwrap_or_default(),
        rule_file: file_name(path),
    }
}

/// Level and status of a correlation rule are plain strings in sigma-rust; they are lowercased
/// and validated here so `-m`, `-D/-u` and the status filters mean the same for every rule.
fn meta_from_correlation(spec: &SigmaCorrelationRule, path: &Path) -> Result<RuleMeta, String> {
    let level = match spec.level.as_deref().map(str::trim) {
        None | Some("") => "informational".to_string(),
        Some(l) => {
            let canonical = canonical_level(l);
            if level_rank(&canonical) == 0 {
                return Err(format!(
                    "correlation rule '{}' has an invalid level '{l}'",
                    spec.title
                ));
            }
            canonical
        }
    };
    let status = match spec.status.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => {
            let lower = s.to_ascii_lowercase();
            if !VALID_STATUSES.contains(&lower.as_str()) {
                return Err(format!(
                    "correlation rule '{}' has an invalid status '{s}'",
                    spec.title
                ));
            }
            Some(lower)
        }
    };
    Ok(RuleMeta {
        title: spec.title.clone(),
        id: spec.id.clone(),
        level,
        status,
        author: spec.author.clone(),
        date: spec.date.clone(),
        modified: None,
        description: spec.description.as_deref().map(trim_block),
        references: spec.references.clone().unwrap_or_default(),
        tags: spec.tags.clone().unwrap_or_default(),
        falsepositives: spec.falsepositives.clone().unwrap_or_default(),
        rule_file: file_name(path),
    })
}

/// YAML block scalars (`description: |`) end with a newline that has no place in a table cell.
fn trim_block(text: &str) -> String {
    text.trim_end().to_string()
}

// --- filters --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Skip {
    Status,
    Level,
    Tag,
}

fn count_skip(stats: &mut LoadStats, skip: Skip) {
    match skip {
        Skip::Status => stats.skipped_status += 1,
        Skip::Level => stats.skipped_level += 1,
        Skip::Tag => stats.skipped_tag += 1,
    }
}

/// Why a rule is left out, checked in the order status → level → tags. The unsupported log
/// source check comes before this and needs the log source, so it lives at the call sites.
fn filter_reason(meta: &RuleMeta, filters: &RuleFilters) -> Option<Skip> {
    let status = meta.status.as_deref();
    let has = |list: &[String], value: &str| list.iter().any(|f| f.eq_ignore_ascii_case(value));
    match status {
        Some("deprecated") if !filters.enable_deprecated => return Some(Skip::Status),
        Some("unsupported") if !filters.enable_unsupported => return Some(Skip::Status),
        _ => {}
    }
    if !filters.include_status.is_empty()
        && !status.is_some_and(|s| has(&filters.include_status, s))
    {
        return Some(Skip::Status);
    }
    if status.is_some_and(|s| has(&filters.exclude_status, s)) {
        return Some(Skip::Status);
    }
    if level_rank(&meta.level) < level_rank(&filters.min_level) {
        return Some(Skip::Level);
    }
    if !filters.include_tag.is_empty() && !meta.tags.iter().any(|t| has(&filters.include_tag, t)) {
        return Some(Skip::Tag);
    }
    if meta.tags.iter().any(|t| has(&filters.exclude_tag, t)) {
        return Some(Skip::Tag);
    }
    None
}

// --- correlation files ----------------------------------------------------------------------------

/// A base document of a correlation file.
struct BaseDoc {
    /// `name:`, else `id:`, else `title:` — the keys a `rules:` entry may use, in lookup order.
    name: String,
    id: Option<String>,
    title: String,
    /// The normalized document, re-parsed when a second correlation needs its own `Rule`.
    value: Value,
    /// The parsed rule, taken by the first correlation that references it (`Rule` is not `Clone`).
    rule: Option<Rule>,
    logsource: LogSourceSpec,
}

/// A correlation document that parsed and resolved; nothing is loaded before the whole file did.
struct PendingCorrelation {
    spec: SigmaCorrelationRule,
    meta: RuleMeta,
    neq: Option<u64>,
    /// Indices into the file's base documents, in `rules:` order.
    resolved: Vec<usize>,
}

fn load_correlation_file(path: &Path, docs: Vec<Value>, filters: &RuleFilters, set: &mut RuleSet) {
    match prepare_correlation_file(path, docs) {
        Ok((bases, pending)) => {
            // A detection document that no correlation of the file references is an ordinary
            // rule that happens to share the file (pySigma loads it the same way).
            // The base rules of a correlation with `generate: true` also report their own matches
            // (Sigma correlation specification), so they are loaded as standalone rules as well.
            let standalone: Vec<Value> = bases
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    let referenced = pending.iter().filter(|p| p.resolved.contains(i));
                    let mut any = false;
                    for p in referenced {
                        any = true;
                        if p.spec.correlation.generate.unwrap_or(false) {
                            return true;
                        }
                    }
                    !any
                })
                .map(|(_, b)| b.value.clone())
                .collect();
            commit_correlations(path, bases, pending, filters, set);
            for doc in standalone {
                load_detection_doc(path, doc, filters, set);
            }
        }
        Err(e) => {
            log_error(&format!("Failed to parse rule {}: {e}", path.display()));
            set.stats.failed += 1;
        }
    }
}

/// Parse every document of a correlation file and resolve every `rules:` entry. Any error fails
/// the file as a whole (amendment A12).
fn prepare_correlation_file(
    path: &Path,
    docs: Vec<Value>,
) -> Result<(Vec<BaseDoc>, Vec<PendingCorrelation>), String> {
    let mut bases: Vec<BaseDoc> = Vec::new();
    let mut correlation_docs = Vec::new();
    for mut doc in docs {
        if is_correlation_doc(&doc) {
            correlation_docs.push(doc);
            continue;
        }
        check_condition_patterns(&doc).map_err(|e| format!("base rule: {e}"))?;
        normalize_detection(&mut doc);
        let rule: Rule =
            yaml_serde::from_value(doc.clone()).map_err(|e| format!("base rule: {e}"))?;
        let name = rule
            .name
            .clone()
            .or_else(|| rule.id.clone())
            .unwrap_or_else(|| rule.title.clone());
        if bases.iter().any(|b: &BaseDoc| b.name == name) {
            return Err(format!(
                "two rules of the file are named '{name}'; correlation references would be ambiguous"
            ));
        }
        bases.push(BaseDoc {
            name,
            id: rule.id.clone(),
            title: rule.title.clone(),
            logsource: LogSourceSpec::from_rule(&rule),
            value: doc,
            rule: Some(rule),
        });
    }
    let mut pending = Vec::with_capacity(correlation_docs.len());
    for doc in correlation_docs {
        let neq = check_correlation_section(&doc)?;
        let spec: SigmaCorrelationRule =
            yaml_serde::from_value(doc).map_err(|e| format!("correlation rule: {e}"))?;
        if crate::correlate::timespan_seconds(&spec.correlation.timespan).is_none() {
            return Err(format!(
                "correlation rule '{}' has an invalid timespan '{}' (use a number followed by s, m, h or d)",
                spec.title, spec.correlation.timespan
            ));
        }
        let meta = meta_from_correlation(&spec, path)?;
        let resolved = resolve_base_rules(&spec, &bases)?;
        pending.push(PendingCorrelation {
            spec,
            meta,
            neq,
            resolved,
        });
    }
    Ok((bases, pending))
}

/// Each `rules:` entry against the file's base rules by `name`, then `id`, then `title`.
fn resolve_base_rules(
    spec: &SigmaCorrelationRule,
    bases: &[BaseDoc],
) -> Result<Vec<usize>, String> {
    let title = &spec.title;
    if spec.correlation.rules.is_empty() {
        return Err(format!("correlation rule '{title}' references no rules"));
    }
    let mut resolved = Vec::with_capacity(spec.correlation.rules.len());
    for entry in &spec.correlation.rules {
        let index = bases
            .iter()
            .position(|b| b.name == *entry)
            .or_else(|| {
                bases
                    .iter()
                    .position(|b| b.id.as_deref() == Some(entry.as_str()))
            })
            .or_else(|| bases.iter().position(|b| b.title == *entry))
            .ok_or_else(|| {
                format!(
                    "correlation rule '{title}' references '{entry}', which is not a rule of the same file"
                )
            })?;
        if resolved.contains(&index) {
            return Err(format!(
                "correlation rule '{title}' references rule '{}' more than once (as '{entry}')",
                bases[index].name
            ));
        }
        resolved.push(index);
    }
    Ok(resolved)
}

fn commit_correlations(
    path: &Path,
    mut bases: Vec<BaseDoc>,
    pending: Vec<PendingCorrelation>,
    filters: &RuleFilters,
    set: &mut RuleSet,
) {
    for PendingCorrelation {
        mut spec,
        meta,
        neq,
        resolved,
    } in pending
    {
        if let Some(bad) = resolved
            .iter()
            .map(|&i| &bases[i])
            .find(|b| !b.logsource.is_supported())
        {
            set.stats.skipped_unsupported_logsource += 1;
            log_warn(&format!(
                "Skipped correlation rule with an unsupported log source ({}): {} ({})",
                bad.logsource, meta.title, meta.rule_file
            ));
            continue;
        }
        if let Some(skip) = filter_reason(&meta, filters) {
            count_skip(&mut set.stats, skip);
            continue;
        }
        let mut base_rules = Vec::with_capacity(resolved.len());
        for (k, &i) in resolved.iter().enumerate() {
            let entry = spec.correlation.rules.get(k).cloned();
            let base = &mut bases[i];
            let rule = match take_rule(base) {
                Ok(rule) => rule,
                Err(e) => {
                    log_error(&format!(
                        "Failed to parse rule {}: base rule: {e}",
                        path.display()
                    ));
                    set.stats.failed += 1;
                    return;
                }
            };
            let mut identifiers: Vec<String> = Vec::new();
            for id in [
                Some(base.name.clone()),
                base.id.clone(),
                Some(base.title.clone()),
                entry,
            ]
            .into_iter()
            .flatten()
            {
                if !identifiers.contains(&id) {
                    identifiers.push(id);
                }
            }
            base_rules.push(BaseRule {
                identifiers,
                meta: meta_from_rule(&rule, path),
                logsource: base.logsource.clone(),
                rule,
            });
        }
        // sigma-rust's own engine matches base events by rule title; our engine goes by index.
        spec.correlation.rules = base_rules.iter().map(|b| b.meta.title.clone()).collect();
        let rule_order = (0..base_rules.len()).collect();
        set.correlations.push(CorrelationRule {
            spec,
            meta,
            base_rules,
            rule_order,
            condition_neq: neq,
        });
    }
}

/// The parsed rule of a base document; re-parsed when another correlation already took it.
fn take_rule(base: &mut BaseDoc) -> Result<Rule, String> {
    match base.rule.take() {
        Some(rule) => Ok(rule),
        None => yaml_serde::from_value(base.value.clone()).map_err(|e| e.to_string()),
    }
}

// --- keyword normalization ------------------------------------------------------------------------

fn normalize_selection(value: &mut Value) {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => {
            let scalar = std::mem::take(value);
            *value = Value::Sequence(vec![wrap_keyword(scalar)]);
        }
        Value::Sequence(items) => {
            if items.iter().all(is_keyword_scalar) {
                for item in items.iter_mut() {
                    let scalar = std::mem::take(item);
                    *item = wrap_keyword(scalar);
                }
            } else if items.iter().all(Value::is_mapping) {
                for item in items.iter_mut() {
                    rewrite_fieldless_keys(item);
                }
            }
            // A mixed list is invalid Sigma; sigma-rust reports it when the rule is parsed.
        }
        Value::Mapping(_) => rewrite_fieldless_keys(value),
        _ => {}
    }
}

fn is_keyword_scalar(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

/// `REPLACE` → `*REPLACE*`; `4624` → `*4624*`; `true` → `*true*`.
fn wrap_keyword(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(wrap_wildcards(&s)),
        Value::Number(n) => Value::String(format!("*{n}*")),
        Value::Bool(b) => Value::String(format!("*{b}*")),
        other => other,
    }
}

/// Surround a keyword with `*` so it matches anywhere, keeping wildcards it already has and
/// keeping a trailing backslash from escaping the appended star.
fn wrap_wildcards(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 3);
    if !s.starts_with('*') {
        out.push('*');
    }
    out.push_str(s);
    if !ends_with_unescaped_star(s) {
        if !trailing_backslashes(s).is_multiple_of(2) {
            out.push('\\');
        }
        out.push('*');
    }
    out
}

fn trailing_backslashes(s: &str) -> usize {
    s.chars().rev().take_while(|c| *c == '\\').count()
}

/// True when the last character is a `*` that is not escaped (an even run of backslashes before it).
fn ends_with_unescaped_star(s: &str) -> bool {
    match s.strip_suffix('*') {
        Some(head) => trailing_backslashes(head).is_multiple_of(2),
        None => false,
    }
}

/// Rewrite the keys of a field map whose field name is empty (`'|all'`) to `raw|...`.
fn rewrite_fieldless_keys(value: &mut Value) {
    let Some(map) = value.as_mapping_mut() else {
        return;
    };
    if !map.keys().any(is_fieldless_key) {
        return;
    }
    let entries = std::mem::take(map);
    let mut rebuilt = Mapping::with_capacity(entries.len());
    for (key, mut val) in entries {
        let key = match key.as_str() {
            Some(k) if field_part(k).is_empty() => {
                let new_key = raw_field_key(k);
                // sigma-rust only accepts strings under contains/startswith/endswith, while a
                // keyword list may hold numbers (`'|all': [4624, 'inside']`).
                if has_string_modifier(&new_key) {
                    stringify_scalars(&mut val);
                }
                Value::String(new_key)
            }
            _ => key,
        };
        rebuilt.insert(key, val);
    }
    *map = rebuilt;
}

fn is_fieldless_key(key: &Value) -> bool {
    key.as_str().is_some_and(|k| field_part(k).is_empty())
}

/// The text before the first `|`.
fn field_part(key: &str) -> &str {
    key.split('|').next().unwrap_or("")
}

/// `'|all'` → `raw|contains|all`, `'|contains|all'` → `raw|contains|all`, `'|re'` → `raw|re`.
fn raw_field_key(key: &str) -> String {
    let modifiers: Vec<&str> = key.split('|').skip(1).collect();
    let has_match_modifier = modifiers
        .iter()
        .any(|m| MATCH_MODIFIERS.contains(&m.trim().to_ascii_lowercase().as_str()));
    let mut out = String::from(RAW_FIELD);
    if !has_match_modifier {
        out.push_str("|contains");
    }
    for m in modifiers {
        out.push('|');
        out.push_str(m);
    }
    out
}

fn has_string_modifier(key: &str) -> bool {
    key.split('|').skip(1).any(|m| {
        matches!(
            m.trim().to_ascii_lowercase().as_str(),
            "contains" | "startswith" | "endswith"
        )
    })
}

/// Numbers and booleans (alone or in a list) become strings.
fn stringify_scalars(value: &mut Value) {
    match value {
        Value::Number(n) => *value = Value::String(n.to_string()),
        Value::Bool(b) => *value = Value::String(b.to_string()),
        Value::Sequence(items) => items.iter_mut().for_each(stringify_scalars),
        _ => {}
    }
}

/// Keys the Sigma correlation specification defines for `correlation:` and its `condition:`.
const CORRELATION_KEYS: &[&str] = &[
    "type",
    "rules",
    "group-by",
    "group_by",
    "timespan",
    "condition",
    "generate",
    "aliases",
];
const CONDITION_KEYS: &[&str] = &["gt", "gte", "lt", "lte", "eq", "neq", "field"];

/// Reject unknown keys in a correlation's `correlation:` / `condition:` sections (serde would
/// silently ignore a typo such as `groupby:`, and the rule would then count across every client)
/// and return the `neq` threshold, which sigma-rust's `CorrelationCondition` cannot hold.
fn check_correlation_section(doc: &Value) -> Result<Option<u64>, String> {
    let title = doc.get("title").and_then(Value::as_str).unwrap_or("?");
    let Some(section) = doc.get("correlation").and_then(Value::as_mapping) else {
        return Err(format!(
            "correlation rule '{title}': 'correlation' must be a mapping"
        ));
    };
    for key in section.keys() {
        let k = key.as_str().unwrap_or("");
        if !CORRELATION_KEYS.contains(&k) {
            return Err(format!(
                "correlation rule '{title}': unknown key '{k}' in 'correlation'"
            ));
        }
    }
    let Some(condition) = section.get("condition") else {
        return Ok(None);
    };
    let Some(condition) = condition.as_mapping() else {
        return Err(format!(
            "correlation rule '{title}': 'condition' must be a mapping"
        ));
    };
    for key in condition.keys() {
        let k = key.as_str().unwrap_or("");
        if !CONDITION_KEYS.contains(&k) {
            return Err(format!(
                "correlation rule '{title}': unknown condition operator '{k}'"
            ));
        }
    }
    match condition.get("neq") {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| {
            format!("correlation rule '{title}': 'neq' must be a non-negative integer")
        }),
    }
}

/// `1 of selection_*` / `all of filter*` must name at least one search identifier. sigma-rust
/// evaluates `all of <nothing>` as true, so a typo in the pattern would make the rule match
/// every event of its log source.
fn check_condition_patterns(doc: &Value) -> Result<(), String> {
    let Some(detection) = doc.get("detection").and_then(Value::as_mapping) else {
        return Ok(());
    };
    let names: Vec<&str> = detection
        .keys()
        .filter_map(Value::as_str)
        .filter(|k| *k != "condition")
        .collect();
    let conditions: Vec<&str> = match detection.get("condition") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Sequence(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    for condition in conditions {
        let words: Vec<&str> = condition
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter(|w| !w.is_empty())
            .collect();
        for w in words.windows(3) {
            let quantifier = w[0].to_ascii_lowercase();
            let is_quantifier = quantifier == "all"
                || quantifier == "any"
                || quantifier.chars().all(|c| c.is_ascii_digit());
            if !is_quantifier || !w[1].eq_ignore_ascii_case("of") {
                continue;
            }
            let pattern = w[2];
            if pattern.eq_ignore_ascii_case("them") {
                continue;
            }
            if !names.iter().any(|n| glob_match(pattern, n)) {
                return Err(format!(
                    "condition '{condition}': '{pattern}' matches no search identifier"
                ));
            }
        }
    }
    Ok(())
}

/// `*` matches any run of characters (search-identifier patterns have no other wildcard).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || !text[first.len()..].ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigma_rust::Event;
    use std::fs;
    use tempfile::tempdir;

    const LINUX_SYSLOG: &str = "    product: linux\n    service: syslog";

    /// A keyword rule (`REPLACE`) with the given metadata.
    fn detection_yaml(
        title: &str,
        level: Option<&str>,
        status: Option<&str>,
        tags: &[&str],
        logsource: &str,
    ) -> String {
        let mut y = format!(
            "title: {title}\nid: id-{}\n",
            title.to_ascii_lowercase().replace(' ', "-")
        );
        if let Some(s) = status {
            y.push_str(&format!("status: {s}\n"));
        }
        if !tags.is_empty() {
            y.push_str("tags:\n");
            for t in tags {
                y.push_str(&format!("    - {t}\n"));
            }
        }
        y.push_str(&format!("logsource:\n{logsource}\n"));
        y.push_str("detection:\n    keywords:\n        - 'REPLACE'\n    condition: keywords\n");
        if let Some(l) = level {
            y.push_str(&format!("level: {l}\n"));
        }
        y
    }

    fn min_level(level: &str) -> RuleFilters {
        RuleFilters {
            min_level: level.to_string(),
            ..Default::default()
        }
    }

    fn write(dir: &Path, name: &str, yaml: &str) {
        fs::write(dir.join(name), yaml).unwrap();
    }

    fn titles(set: &RuleSet) -> Vec<String> {
        let mut t: Vec<String> = set.rules.iter().map(|r| r.meta.title.clone()).collect();
        t.sort();
        t
    }

    fn parse_doc(yaml: &str) -> Value {
        yaml_serde::from_str(yaml).unwrap()
    }

    fn message_event(message: &str) -> Event {
        let mut event = Event::new();
        event.insert("message", message);
        event.insert(RAW_FIELD, message);
        event
    }

    fn shipped_rules_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("rules")
    }

    // --- the shipped rule set ---------------------------------------------------------------------

    #[test]
    fn shipped_rules_load_completely() {
        let set = load_rules(&shipped_rules_dir(), &min_level("informational"));
        assert_eq!(set.stats.failed, 0, "no rule may fail to load");
        assert_eq!(set.stats.skipped_unsupported_logsource, 0);
        assert_eq!(set.stats.skipped_status, 0);
        assert_eq!(set.stats.skipped_level, 0);
        assert_eq!(set.stats.skipped_tag, 0);
        assert_eq!(set.stats.files_seen, 206);
        assert_eq!(set.rules.len(), 204);
        assert_eq!(set.correlations.len(), 2);
        assert_eq!(set.stats.loaded, 204);
        assert_eq!(set.stats.correlations, 2);

        // The SigmaHQ rules for audit records and Sysmon for Linux, by their file name prefixes
        // (rules/sigma/linux/{auditd,process_creation,network_connection,file_event})
        let sysmon_or_audit = [
            "lnx_auditd_",
            "proc_creation_lnx_",
            "net_connection_lnx_",
            "file_event_lnx_",
        ];
        let count = |prefix: &str| {
            set.rules
                .iter()
                .filter(|r| r.meta.rule_file.starts_with(prefix))
                .count()
        };
        assert_eq!(count("lnx_auditd_"), 53);
        assert_eq!(count("proc_creation_lnx_"), 122);
        assert_eq!(count("net_connection_lnx_"), 5);
        assert_eq!(count("file_event_lnx_"), 8);

        let mut expected: Vec<String> = [
            // SigmaHQ rules under rules/sigma
            "Modifying Crontab",
            "Suspicious OpenSSH Daemon Error",
            "Disabling Security Tools - Builtin",
            "Suspicious Named Error",
            "Apache Segmentation Fault",
            "Apache Threading Error",
            "Nginx Core Dump",
            // iwatobi detection rules under rules/iwatobi
            "PHP-FPM Child Process Exited On Signal",
            "PHP-FPM Child Shell Error Output",
            "PHP Outbound HTTP Request From Command Line Code",
            "PHP POST Content-Length Exceeds Limit",
            "PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure)",
            "PHP Session ID Too Long Or Illegal Characters (PHP2Shell Memory Disclosure)",
            "Shell Error Output In Apache Error Log",
            "Apache Worker Process Exited On Abort Or Bus Error Signal",
            "PHP2Shell PoC Memory Pressure Request",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        expected.sort();
        let mut others: Vec<String> = set
            .rules
            .iter()
            .filter(|r| {
                !sysmon_or_audit
                    .iter()
                    .any(|p| r.meta.rule_file.starts_with(p))
            })
            .map(|r| r.meta.title.clone())
            .collect();
        others.sort();
        assert_eq!(others, expected);

        // Base rules of the correlation files must not be loaded as detection rules.
        assert!(!set.rules.iter().any(|r| {
            r.meta.title.starts_with("PHP2Shell Chain - ")
                || r.meta.title == "POST Request To Web Root Or PHP Index"
        }));

        let chain = set
            .correlations
            .iter()
            .find(|c| {
                c.meta.title
                    == "PHP2Shell Exploitation Chain (Memory Pressure, Memory Disclosure, Worker Crash)"
            })
            .expect("the PHP2Shell chain correlation");
        assert_eq!(chain.rule_order, vec![0, 1, 2]);
        let names: Vec<&str> = chain.base_rules.iter().map(|b| b.name()).collect();
        assert_eq!(
            names,
            vec![
                "php2shell_chain_pre_script_oom",
                "php2shell_chain_session_id_too_long",
                "php2shell_chain_apache_worker_crash"
            ]
        );
        assert_eq!(
            chain.spec.correlation.rules,
            vec![
                "PHP2Shell Chain - Pre-Script Memory Exhaustion",
                "PHP2Shell Chain - Session ID Too Long",
                "PHP2Shell Chain - Apache Worker Crash"
            ]
        );
        assert_eq!(chain.meta.level, "critical");
        assert_eq!(chain.meta.status.as_deref(), Some("experimental"));
        assert_eq!(
            chain.meta.id.as_deref(),
            Some("fe94df42-c06f-4054-9070-3430525cec31")
        );
        assert_eq!(chain.meta.rule_file, "php2shell_exploitation_chain.yml");
        assert_eq!(chain.meta.modified, None);
        assert!(chain.meta.tags.iter().any(|t| t == "cve.2026-109618"));
        assert_eq!(chain.spec.correlation.timespan, "5m");
        assert_eq!(
            chain.base_rules[0].logsource,
            LogSourceSpec::new(Some("php"), None, Some("error_log"))
        );
        assert_eq!(
            chain.base_rules[2].logsource,
            LogSourceSpec::new(None, None, Some("apache"))
        );
        assert_eq!(chain.base_rules[0].meta.level, "high");
        assert_eq!(
            chain.base_rules[0].meta.rule_file,
            "php2shell_exploitation_chain.yml"
        );

        let rapid = set
            .correlations
            .iter()
            .find(|c| c.meta.title == "Rapid Repeated POST Requests To PHP Index Page")
            .expect("the rapid POST correlation");
        assert_eq!(rapid.rule_order, vec![0]);
        assert_eq!(rapid.base_rules.len(), 1);
        assert_eq!(rapid.base_rules[0].name(), "post_to_php_index");
        assert_eq!(
            rapid.spec.correlation.rules,
            vec!["POST Request To Web Root Or PHP Index"]
        );
        assert_eq!(rapid.meta.level, "medium");
        assert_eq!(
            rapid.spec.correlation.group_by.as_deref(),
            Some(&["c-ip".to_string()][..])
        );
        assert_eq!(rapid.spec.correlation.timespan, "60s");
        assert_eq!(
            rapid
                .spec
                .correlation
                .condition
                .as_ref()
                .and_then(|c| c.gte),
            Some(3)
        );
        assert_eq!(rapid.base_rules[0].meta.level, "informational");
    }

    #[test]
    fn shipped_rule_metadata_is_complete() {
        let set = load_rules(&shipped_rules_dir(), &RuleFilters::default());
        let cron = set
            .rules
            .iter()
            .find(|r| r.meta.title == "Modifying Crontab")
            .expect("the SigmaHQ crontab rule");
        let m = &cron.meta;
        assert_eq!(
            m.id.as_deref(),
            Some("af202fd3-7bff-4212-a25a-fb34606cfcbe")
        );
        assert_eq!(m.level, "medium");
        assert_eq!(m.status.as_deref(), Some("test"));
        assert_eq!(m.author.as_deref(), Some("Pawel Mazur"));
        assert_eq!(m.date.as_deref(), Some("2022-04-16"));
        assert_eq!(m.modified, None);
        assert_eq!(
            m.description.as_deref(),
            Some("Detects suspicious modification of crontab file.")
        );
        assert_eq!(m.references.len(), 1);
        assert_eq!(
            m.tags,
            vec![
                "attack.privilege-escalation",
                "attack.execution",
                "attack.persistence",
                "attack.t1053.003"
            ]
        );
        assert_eq!(m.falsepositives, vec!["Legitimate modification of crontab"]);
        assert_eq!(m.rule_file, "lnx_cron_crontab_file_modification.yml");
        assert_eq!(
            cron.logsource,
            LogSourceSpec::new(Some("linux"), None, Some("cron"))
        );

        let sshd = set
            .rules
            .iter()
            .find(|r| r.meta.title == "Suspicious OpenSSH Daemon Error")
            .unwrap();
        assert_eq!(sshd.meta.modified.as_deref(), Some("2021-11-27"));

        // Block-scalar descriptions lose their trailing newline.
        let php = set
            .rules
            .iter()
            .find(|r| r.meta.title == "PHP POST Content-Length Exceeds Limit")
            .unwrap();
        let d = php.meta.description.as_deref().unwrap();
        assert!(d.starts_with("Detects the PHP warning raised when a POST body"));
        assert!(!d.ends_with('\n'));
        assert_eq!(php.meta.level, "low");
    }

    #[test]
    fn shipped_keyword_rules_match_real_log_lines() {
        let set = load_rules(&shipped_rules_dir(), &RuleFilters::default());
        let rule_by_title = |title: &str| -> &LoadedRule {
            set.rules
                .iter()
                .find(|r| r.meta.title == title)
                .unwrap_or_else(|| panic!("rule {title}"))
        };
        assert!(
            rule_by_title("Modifying Crontab")
                .rule
                .is_match(&message_event("(user) REPLACE (user)"))
        );
        assert!(
            !rule_by_title("Modifying Crontab")
                .rule
                .is_match(&message_event("(user) LIST (user)"))
        );
        // Case-insensitive: the rule says `Segmentation Fault`, the log has a lowercase f.
        assert!(
            rule_by_title("Apache Segmentation Fault")
                .rule
                .is_match(&message_event(
                    "AH00051: child pid 31 exit signal Segmentation fault (11), possible coredump in /etc/apache2"
                ))
        );
        // An inner `*` keeps its wildcard meaning after wrapping.
        let oom = rule_by_title(
            "PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure)",
        );
        assert!(oom.rule.is_match(&message_event(
            "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"
        )));
        assert!(!oom.rule.is_match(&message_event(
            "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in /var/www/html/index.php on line 12"
        )));
        // Field-based selections are untouched and still match exact values.
        let poc = rule_by_title("PHP2Shell PoC Memory Pressure Request");
        let mut access = Event::new();
        access.insert("cs-method", "POST");
        access.insert("cs-uri-query", "/?q0000000=v&q0000001=v&q0000002=v");
        assert!(poc.rule.is_match(&access));
        let mut get = Event::new();
        get.insert("cs-method", "GET");
        get.insert("cs-uri-query", "/?q0000000=v&q0000001=v&q0000002=v");
        assert!(!poc.rule.is_match(&get));
    }

    // --- normalize_detection ------------------------------------------------------------------------

    #[test]
    fn keywords_are_wrapped_in_wildcards() {
        let mut doc = parse_doc(
            "title: t\ndetection:\n  keywords:\n    - 'REPLACE'\n    - 'Trojan*FOUND'\n    - '*already*'\n    - 'ends*'\n    - '*starts'\n    - 'a*b*c'\n  condition: keywords\n",
        );
        normalize_detection(&mut doc);
        let expected = parse_doc(
            "title: t\ndetection:\n  keywords:\n    - '*REPLACE*'\n    - '*Trojan*FOUND*'\n    - '*already*'\n    - '*ends*'\n    - '*starts*'\n    - '*a*b*c*'\n  condition: keywords\n",
        );
        assert_eq!(doc, expected);
    }

    #[test]
    fn trailing_backslashes_keep_the_appended_star_a_wildcard() {
        // one trailing backslash: it would escape the appended star, so one more is added
        assert_eq!(wrap_wildcards("C:\\Temp\\"), "*C:\\Temp\\\\*");
        // two trailing backslashes form an escaped backslash: nothing to add
        assert_eq!(wrap_wildcards("C:\\Temp\\\\"), "*C:\\Temp\\\\*");
        // three: again one more
        assert_eq!(wrap_wildcards("x\\\\\\"), "*x\\\\\\\\*");
        // an escaped star at the end is a literal star, so a wildcard is still appended
        assert_eq!(wrap_wildcards("foo\\*"), "*foo\\**");
        // an unescaped star after an escaped backslash is a wildcard already
        assert_eq!(wrap_wildcards("foo\\\\*"), "*foo\\\\*");
        // escaped star at the start still gets the prefix
        assert_eq!(wrap_wildcards("\\*foo"), "*\\*foo*");
        assert_eq!(wrap_wildcards("*"), "*");
        assert_eq!(wrap_wildcards(""), "**");
        assert_eq!(wrap_wildcards("\\"), "*\\\\*");
        assert_eq!(wrap_wildcards("a?b"), "*a?b*");
    }

    #[test]
    fn wrapped_backslash_keyword_still_matches_through_sigma_rust() {
        // The keyword ends in a backslash; after wrapping, the backslash must stay literal and
        // the star must stay a wildcard.
        let mut doc = parse_doc(
            "title: t\nlogsource:\n  product: linux\ndetection:\n  keywords:\n    - 'Temp\\'\n  condition: keywords\n",
        );
        normalize_detection(&mut doc);
        let kw = doc["detection"]["keywords"][0].as_str().unwrap();
        assert_eq!(kw, "*Temp\\\\*");
        let rule: Rule = yaml_serde::from_value(doc).unwrap();
        assert!(rule.is_match(&message_event("copy to C:\\Temp\\evil.exe done")));
        assert!(!rule.is_match(&message_event("copy to C:\\Temp evil.exe done")));
    }

    #[test]
    fn numbers_and_bools_become_wrapped_strings() {
        let mut doc = parse_doc(
            "title: t\ndetection:\n  ids:\n    - 4624\n    - 4625\n    - true\n    - 1.5\n  condition: ids\n",
        );
        normalize_detection(&mut doc);
        let expected = parse_doc(
            "title: t\ndetection:\n  ids:\n    - '*4624*'\n    - '*4625*'\n    - '*true*'\n    - '*1.5*'\n  condition: ids\n",
        );
        assert_eq!(doc, expected);
    }

    #[test]
    fn scalar_selection_becomes_a_one_element_list() {
        let mut doc =
            parse_doc("title: t\ndetection:\n  keywords: REPLACE\n  condition: keywords\n");
        normalize_detection(&mut doc);
        assert_eq!(
            doc,
            parse_doc(
                "title: t\ndetection:\n  keywords:\n    - '*REPLACE*'\n  condition: keywords\n"
            )
        );
        let mut num = parse_doc("title: t\ndetection:\n  sel: 4624\n  condition: sel\n");
        normalize_detection(&mut num);
        assert_eq!(
            num,
            parse_doc("title: t\ndetection:\n  sel:\n    - '*4624*'\n  condition: sel\n")
        );
    }

    #[test]
    fn fieldless_keys_are_rewritten_to_raw() {
        // the lnx_susp_jexboss shape
        let mut doc = parse_doc(
            "title: t\ndetection:\n  keywords:\n    '|all':\n      - 'JexBoss'\n      - 'jboss'\n  condition: keywords\n",
        );
        normalize_detection(&mut doc);
        assert_eq!(
            doc,
            parse_doc(
                "title: t\ndetection:\n  keywords:\n    'raw|contains|all':\n      - 'JexBoss'\n      - 'jboss'\n  condition: keywords\n"
            )
        );

        let cases = [
            ("'|all'", "raw|contains|all"),
            ("'|contains|all'", "raw|contains|all"),
            ("'|re'", "raw|re"),
            ("'|startswith'", "raw|startswith"),
            ("'|endswith|all'", "raw|endswith|all"),
            ("'|windash'", "raw|contains|windash"),
            ("'|cased'", "raw|contains|cased"),
            ("'|CONTAINS'", "raw|CONTAINS"),
            ("''", "raw|contains"),
        ];
        for (key, expected) in cases {
            let mut doc = parse_doc(&format!(
                "title: t\ndetection:\n  sel:\n    {key}: ['x']\n  condition: sel\n"
            ));
            normalize_detection(&mut doc);
            let sel = doc["detection"]["sel"].as_mapping().unwrap();
            let keys: Vec<&str> = sel.keys().filter_map(Value::as_str).collect();
            assert_eq!(keys, vec![expected], "key {key}");
            // values of field maps are never wrapped
            assert_eq!(sel[expected], parse_doc("['x']"));
        }
    }

    #[test]
    fn fieldless_keys_in_a_list_of_maps_are_rewritten_and_order_is_kept() {
        let mut doc = parse_doc(
            "title: t\ndetection:\n  sel:\n    - cs-method: POST\n      '|contains': 'a'\n      sc-status: 200\n    - '|re': 'b.*'\n  condition: sel\n",
        );
        normalize_detection(&mut doc);
        let sel = doc["detection"]["sel"].as_sequence().unwrap();
        let first: Vec<&str> = sel[0]
            .as_mapping()
            .unwrap()
            .keys()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(first, vec!["cs-method", "raw|contains", "sc-status"]);
        assert_eq!(sel[0]["cs-method"], Value::from("POST"));
        assert_eq!(sel[0]["raw|contains"], Value::from("a"));
        assert_eq!(sel[0]["sc-status"], Value::from(200));
        let second: Vec<&str> = sel[1]
            .as_mapping()
            .unwrap()
            .keys()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(second, vec!["raw|re"]);
    }

    #[test]
    fn field_selections_and_condition_are_untouched() {
        let yaml = "title: t\ndetection:\n  selection:\n    cs-method: POST\n    cs-uri-query|contains: 'q0000000=v'\n    sc-status:\n      - 200\n      - 302\n    cs-referer: null\n  filter:\n    - c-ip: 10.0.0.1\n    - c-ip|cidr: 10.0.0.0/8\n  condition: selection and not filter\n";
        let mut doc = parse_doc(yaml);
        normalize_detection(&mut doc);
        assert_eq!(doc, parse_doc(yaml));
    }

    #[test]
    fn documents_without_detection_are_untouched() {
        let correlation = "title: c\ncorrelation:\n  type: event_count\n  rules:\n    - a\n  timespan: 1m\n  condition:\n    gte: 3\n";
        let mut doc = parse_doc(correlation);
        normalize_detection(&mut doc);
        assert_eq!(doc, parse_doc(correlation));

        let mut scalar = Value::from("just a string");
        normalize_detection(&mut scalar);
        assert_eq!(scalar, Value::from("just a string"));

        let mut null = Value::Null;
        normalize_detection(&mut null);
        assert_eq!(null, Value::Null);

        // `detection` that is not a mapping is left for sigma-rust to reject
        let odd = "title: t\ndetection: just text\n";
        let mut doc = parse_doc(odd);
        normalize_detection(&mut doc);
        assert_eq!(doc, parse_doc(odd));

        // a mixed list (keywords and maps) is invalid Sigma and is left alone
        let mixed =
            "title: t\ndetection:\n  sel:\n    - plain\n    - field: value\n  condition: sel\n";
        let mut doc = parse_doc(mixed);
        normalize_detection(&mut doc);
        assert_eq!(doc, parse_doc(mixed));
    }

    #[test]
    fn normalized_rule_matches_anywhere_in_the_message() {
        let yaml = "title: Modifying Crontab\nlogsource:\n  product: linux\n  service: cron\ndetection:\n  keywords:\n    - 'REPLACE'\n  condition: keywords\n";
        let mut doc = parse_doc(yaml);
        let event = message_event("(user) REPLACE (user)");

        // sigma-rust alone matches keywords against whole values, so the raw rule misses
        let raw: Rule = yaml_serde::from_value(doc.clone()).unwrap();
        assert!(!raw.is_match(&event));

        normalize_detection(&mut doc);
        let rule: Rule = yaml_serde::from_value(doc).unwrap();
        assert!(rule.is_match(&event));
        assert!(!rule.is_match(&message_event("(user) LIST (user)")));
    }

    #[test]
    fn normalized_fieldless_all_selection_matches_raw() {
        let yaml = "title: JexBoss\nlogsource:\n  product: linux\ndetection:\n  keywords:\n    '|all':\n      - 'jexboss'\n      - 'jboss'\n  condition: keywords\n";
        let mut doc = parse_doc(yaml);
        normalize_detection(&mut doc);
        let rule: Rule = yaml_serde::from_value(doc).unwrap();
        assert!(rule.is_match(&message_event(
            "GET /jmx-console/ HTTP/1.1 JexBoss scan against jboss"
        )));
        assert!(!rule.is_match(&message_event("JexBoss alone")));
    }

    // --- loading and filters -------------------------------------------------------------------------

    #[test]
    fn min_level_filter_keeps_only_high_and_critical() {
        let dir = tempdir().unwrap();
        for level in ["informational", "low", "medium", "high", "critical"] {
            write(
                dir.path(),
                &format!("{level}.yml"),
                &detection_yaml(
                    &format!("Rule {level}"),
                    Some(level),
                    None,
                    &[],
                    LINUX_SYSLOG,
                ),
            );
        }
        // a rule without a level counts as informational
        write(
            dir.path(),
            "none.yml",
            &detection_yaml("Rule none", None, None, &[], LINUX_SYSLOG),
        );

        let all = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(all.stats.files_seen, 6);
        assert_eq!(all.rules.len(), 6);
        assert_eq!(all.stats.loaded, 6);
        assert_eq!(all.stats.skipped_level, 0);
        let none = all
            .rules
            .iter()
            .find(|r| r.meta.title == "Rule none")
            .unwrap();
        assert_eq!(none.meta.level, "informational");

        let high = load_rules(dir.path(), &min_level("high"));
        assert_eq!(titles(&high), vec!["Rule critical", "Rule high"]);
        assert_eq!(high.stats.skipped_level, 4);
        assert_eq!(high.stats.loaded, 2);

        let crit = load_rules(dir.path(), &min_level("crit"));
        assert_eq!(titles(&crit), vec!["Rule critical"]);
        assert_eq!(crit.stats.skipped_level, 5);

        let info = load_rules(dir.path(), &min_level("info"));
        assert_eq!(info.rules.len(), 6);
    }

    #[test]
    fn status_filters() {
        let dir = tempdir().unwrap();
        for status in [
            "stable",
            "test",
            "experimental",
            "deprecated",
            "unsupported",
        ] {
            write(
                dir.path(),
                &format!("{status}.yml"),
                &detection_yaml(
                    &format!("Rule {status}"),
                    Some("high"),
                    Some(status),
                    &[],
                    LINUX_SYSLOG,
                ),
            );
        }
        write(
            dir.path(),
            "nostatus.yml",
            &detection_yaml("Rule nostatus", Some("high"), None, &[], LINUX_SYSLOG),
        );

        let default = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(
            titles(&default),
            vec![
                "Rule experimental",
                "Rule nostatus",
                "Rule stable",
                "Rule test"
            ]
        );
        assert_eq!(default.stats.skipped_status, 2);
        let stable = default
            .rules
            .iter()
            .find(|r| r.meta.title == "Rule stable")
            .unwrap();
        assert_eq!(stable.meta.status.as_deref(), Some("stable"));
        let nostatus = default
            .rules
            .iter()
            .find(|r| r.meta.title == "Rule nostatus")
            .unwrap();
        assert_eq!(nostatus.meta.status, None);

        let deprecated = load_rules(
            dir.path(),
            &RuleFilters {
                enable_deprecated: true,
                ..Default::default()
            },
        );
        assert_eq!(deprecated.rules.len(), 5);
        assert!(titles(&deprecated).contains(&"Rule deprecated".to_string()));
        assert_eq!(deprecated.stats.skipped_status, 1);

        let both = load_rules(
            dir.path(),
            &RuleFilters {
                enable_deprecated: true,
                enable_unsupported: true,
                ..Default::default()
            },
        );
        assert_eq!(both.rules.len(), 6);
        assert_eq!(both.stats.skipped_status, 0);

        // --include-status: only the listed statuses; rules without a status are dropped too
        let include = load_rules(
            dir.path(),
            &RuleFilters {
                include_status: vec!["test".to_string(), "STABLE".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(titles(&include), vec!["Rule stable", "Rule test"]);
        assert_eq!(include.stats.skipped_status, 4);

        // --include-status deprecated does not override -D
        let include_deprecated = load_rules(
            dir.path(),
            &RuleFilters {
                include_status: vec!["deprecated".to_string()],
                ..Default::default()
            },
        );
        assert!(include_deprecated.rules.is_empty());
        assert_eq!(include_deprecated.stats.skipped_status, 6);

        let exclude = load_rules(
            dir.path(),
            &RuleFilters {
                exclude_status: vec!["experimental".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(
            titles(&exclude),
            vec!["Rule nostatus", "Rule stable", "Rule test"]
        );
        assert_eq!(exclude.stats.skipped_status, 3);
    }

    #[test]
    fn tag_filters() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "exec.yml",
            &detection_yaml(
                "Rule exec",
                Some("high"),
                None,
                &["attack.execution", "attack.t1059"],
                LINUX_SYSLOG,
            ),
        );
        write(
            dir.path(),
            "persist.yml",
            &detection_yaml(
                "Rule persist",
                Some("high"),
                None,
                &["attack.persistence", "attack.t1053.003"],
                LINUX_SYSLOG,
            ),
        );
        write(
            dir.path(),
            "notags.yml",
            &detection_yaml("Rule notags", Some("high"), None, &[], LINUX_SYSLOG),
        );

        let include = load_rules(
            dir.path(),
            &RuleFilters {
                include_tag: vec!["attack.execution".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(titles(&include), vec!["Rule exec"]);
        assert_eq!(include.stats.skipped_tag, 2);

        let include_two = load_rules(
            dir.path(),
            &RuleFilters {
                include_tag: vec!["attack.t1059".to_string(), "attack.persistence".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(titles(&include_two), vec!["Rule exec", "Rule persist"]);

        let exclude = load_rules(
            dir.path(),
            &RuleFilters {
                exclude_tag: vec!["ATTACK.PERSISTENCE".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(titles(&exclude), vec!["Rule exec", "Rule notags"]);
        assert_eq!(exclude.stats.skipped_tag, 1);
    }

    #[test]
    fn filters_apply_in_order_and_count_once_per_rule() {
        // status is checked before level, level before tags
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "a.yml",
            &detection_yaml(
                "Rule a",
                Some("low"),
                Some("deprecated"),
                &["attack.execution"],
                LINUX_SYSLOG,
            ),
        );
        write(
            dir.path(),
            "b.yml",
            &detection_yaml(
                "Rule b",
                Some("low"),
                Some("test"),
                &["attack.execution"],
                LINUX_SYSLOG,
            ),
        );
        let set = load_rules(
            dir.path(),
            &RuleFilters {
                min_level: "high".to_string(),
                exclude_tag: vec!["attack.execution".to_string()],
                ..Default::default()
            },
        );
        assert!(set.rules.is_empty());
        assert_eq!(set.stats.skipped_status, 1);
        assert_eq!(set.stats.skipped_level, 1);
        assert_eq!(set.stats.skipped_tag, 0);
    }

    #[test]
    fn unsupported_logsources_are_skipped() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "windows.yml",
            &detection_yaml(
                "Rule windows",
                Some("high"),
                None,
                &[],
                "    product: windows\n    service: security",
            ),
        );
        write(
            dir.path(),
            "registry.yml",
            &detection_yaml(
                "Rule registry",
                Some("high"),
                None,
                &[],
                "    product: windows\n    category: registry_set",
            ),
        );
        write(
            dir.path(),
            "macos.yml",
            &detection_yaml(
                "Rule macos",
                Some("high"),
                None,
                &[],
                "    product: macos\n    category: process_creation",
            ),
        );
        write(
            dir.path(),
            "sshd.yml",
            &detection_yaml(
                "Rule sshd",
                Some("high"),
                None,
                &[],
                "    product: linux\n    service: sshd",
            ),
        );
        write(
            dir.path(),
            "apache.yml",
            &detection_yaml(
                "Rule apache",
                Some("high"),
                None,
                &[],
                "    service: apache",
            ),
        );
        // an unsupported rule that would also fail the level filter counts as unsupported only
        write(
            dir.path(),
            "windows_low.yml",
            &detection_yaml(
                "Rule windows low",
                Some("low"),
                None,
                &[],
                "    product: windows",
            ),
        );
        let set = load_rules(dir.path(), &min_level("high"));
        assert_eq!(titles(&set), vec!["Rule apache", "Rule sshd"]);
        assert_eq!(set.stats.skipped_unsupported_logsource, 4);
        assert_eq!(set.stats.skipped_level, 0);
        assert_eq!(set.stats.failed, 0);
    }

    #[test]
    fn broken_files_are_counted_and_do_not_stop_the_load() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "unclosed.yml",
            "title: [unclosed\nlevel: high\n",
        );
        write(
            dir.path(),
            "badlevel.yml",
            &detection_yaml("Rule badlevel", Some("urgent"), None, &[], LINUX_SYSLOG),
        );
        write(dir.path(), "empty.yml", "");
        write(dir.path(), "comments.yaml", "# nothing here\n");
        write(dir.path(), "scalar.yml", "just a string\n");
        write(
            dir.path(),
            "nodetection.yml",
            "title: No detection\nlogsource:\n    product: linux\nlevel: high\n",
        );
        write(
            dir.path(),
            "undefined_identifier.yml",
            "title: Undefined\nlogsource:\n    product: linux\ndetection:\n    keywords:\n        - 'x'\n    condition: keywords and other\nlevel: high\n",
        );
        write(dir.path(), "notes.txt", "title: Not a rule\n");
        write(
            dir.path(),
            "good.YML",
            &detection_yaml("Rule good", Some("high"), None, &[], LINUX_SYSLOG),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.files_seen, 8, ".txt is not a rule file");
        assert_eq!(titles(&set), vec!["Rule good"]);
        assert_eq!(set.stats.failed, 7);
        assert_eq!(set.stats.loaded, 1);
    }

    #[test]
    fn a_multi_document_detection_file_loads_every_document() {
        let dir = tempdir().unwrap();
        let yaml = format!(
            "{}---\n{}---\n",
            detection_yaml("Rule one", Some("high"), None, &[], LINUX_SYSLOG),
            detection_yaml("Rule two", Some("low"), None, &[], LINUX_SYSLOG)
        );
        write(dir.path(), "two.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(titles(&set), vec!["Rule one", "Rule two"]);
        assert_eq!(set.stats.failed, 0);
        assert!(set.rules.iter().all(|r| r.meta.rule_file == "two.yml"));
    }

    #[test]
    fn a_single_file_path_is_accepted() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "one.yaml",
            &detection_yaml("Rule one", Some("high"), None, &[], LINUX_SYSLOG),
        );
        write(dir.path(), "two.txt", "title: x\n");
        let set = load_rules(&dir.path().join("one.yaml"), &RuleFilters::default());
        assert_eq!(set.stats.files_seen, 1);
        assert_eq!(titles(&set), vec!["Rule one"]);
        assert_eq!(set.rules[0].meta.rule_file, "one.yaml");

        let txt = load_rules(&dir.path().join("two.txt"), &RuleFilters::default());
        assert_eq!(txt.stats.files_seen, 0);
        assert!(txt.rules.is_empty());

        let missing = load_rules(&dir.path().join("missing.yml"), &RuleFilters::default());
        assert_eq!(missing.stats.files_seen, 0);
        assert!(missing.rules.is_empty());
    }

    #[test]
    fn nested_directories_are_walked_in_sorted_order() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("b/deep")).unwrap();
        fs::create_dir_all(dir.path().join("a")).unwrap();
        write(
            dir.path(),
            "b/deep/z.yml",
            &detection_yaml("Rule z", Some("high"), None, &[], LINUX_SYSLOG),
        );
        write(
            dir.path(),
            "a/y.yml",
            &detection_yaml("Rule y", Some("high"), None, &[], LINUX_SYSLOG),
        );
        write(
            dir.path(),
            "x.yml",
            &detection_yaml("Rule x", Some("high"), None, &[], LINUX_SYSLOG),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        let order: Vec<&str> = set.rules.iter().map(|r| r.meta.title.as_str()).collect();
        assert_eq!(order, vec!["Rule y", "Rule z", "Rule x"]);
        assert_eq!(set.stats.files_seen, 3);
    }

    // --- correlation files ----------------------------------------------------------------------------

    const BASE_RULES: &str = "---
title: Base One
name: base_by_name
id: base-one-id
status: experimental
logsource:
    product: linux
    service: sshd
detection:
    keywords:
        - 'one'
    condition: keywords
level: low
---
title: Base Two
id: base-two-id
logsource:
    product: linux
    service: cron
detection:
    keywords:
        - 'two'
    condition: keywords
---
title: Base Three Title
logsource:
    service: apache
detection:
    keywords:
        - 'three'
    condition: keywords
";

    fn correlation_yaml(extra_meta: &str, rules: &[&str]) -> String {
        let mut y = format!(
            "title: Chain\nid: chain-id\n{extra_meta}correlation:\n    type: temporal\n    rules:\n"
        );
        for r in rules {
            y.push_str(&format!("        - {r}\n"));
        }
        y.push_str("    timespan: 5m\n");
        y
    }

    #[test]
    fn correlation_file_resolves_rules_by_name_id_and_title() {
        let dir = tempdir().unwrap();
        let yaml = format!(
            "{}{}",
            correlation_yaml(
                "status: experimental\nlevel: HIGH\ntags:\n    - attack.t1190\n",
                &["base_by_name", "base-two-id", "Base Three Title"]
            ),
            BASE_RULES
        );
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &min_level("informational"));
        assert_eq!(set.stats.failed, 0);
        assert!(set.rules.is_empty(), "base rules are not standalone rules");
        assert_eq!(set.stats.loaded, 0);
        assert_eq!(set.stats.correlations, 1);
        assert_eq!(set.correlations.len(), 1);
        let corr = &set.correlations[0];
        assert_eq!(corr.meta.title, "Chain");
        assert_eq!(corr.meta.id.as_deref(), Some("chain-id"));
        assert_eq!(corr.meta.level, "high", "levels are lowercased");
        assert_eq!(corr.meta.status.as_deref(), Some("experimental"));
        assert_eq!(corr.meta.tags, vec!["attack.t1190"]);
        assert_eq!(corr.meta.rule_file, "chain.yml");
        assert_eq!(corr.rule_order, vec![0, 1, 2]);
        let names: Vec<&str> = corr.base_rules.iter().map(|b| b.name()).collect();
        assert_eq!(
            names,
            vec!["base_by_name", "base-two-id", "Base Three Title"]
        );
        assert_eq!(
            corr.spec.correlation.rules,
            vec!["Base One", "Base Two", "Base Three Title"]
        );
        assert_eq!(corr.base_rules[0].meta.level, "low");
        assert_eq!(
            corr.base_rules[0].meta.status.as_deref(),
            Some("experimental")
        );
        assert_eq!(corr.base_rules[1].meta.level, "informational");
        assert_eq!(corr.base_rules[1].meta.id.as_deref(), Some("base-two-id"));
        assert_eq!(corr.base_rules[2].meta.id, None);
        assert_eq!(
            corr.base_rules[2].logsource,
            LogSourceSpec::new(None, None, Some("apache"))
        );
        // base rules are normalized like detection rules
        assert!(
            corr.base_rules[0]
                .rule
                .is_match(&message_event("number one here"))
        );
        assert!(
            !corr.base_rules[0]
                .rule
                .is_match(&message_event("number two here"))
        );
    }

    #[test]
    fn correlation_document_may_come_after_its_base_rules() {
        let dir = tempdir().unwrap();
        let yaml = format!(
            "{}---\n{}",
            BASE_RULES.trim_start_matches("---\n"),
            correlation_yaml("level: medium\n", &["base_by_name"])
        );
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 0);
        assert_eq!(set.correlations.len(), 1);
        assert_eq!(set.correlations[0].base_rules.len(), 1);
        assert_eq!(set.correlations[0].rule_order, vec![0]);
        assert_eq!(set.correlations[0].spec.correlation.rules, vec!["Base One"]);
    }

    #[test]
    fn unresolvable_rules_entry_fails_the_whole_file() {
        let dir = tempdir().unwrap();
        let yaml = format!(
            "{}{}",
            correlation_yaml("level: high\n", &["base_by_name", "does_not_exist"]),
            BASE_RULES
        );
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 1);
        assert!(set.rules.is_empty());
        assert!(set.correlations.is_empty());
        assert_eq!(set.stats.loaded, 0);
        assert_eq!(set.stats.correlations, 0);
    }

    #[test]
    fn duplicate_rules_entries_fail_the_whole_file() {
        let dir = tempdir().unwrap();
        // the same base rule referenced by name and by id
        let yaml = format!(
            "{}{}",
            correlation_yaml("level: high\n", &["base_by_name", "base-one-id"]),
            BASE_RULES
        );
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 1);
        assert!(set.correlations.is_empty());
        assert!(set.rules.is_empty());
    }

    #[test]
    fn broken_base_rule_or_correlation_fails_the_whole_file() {
        let dir = tempdir().unwrap();
        let broken_base = format!(
            "{}---\ntitle: Broken\nlogsource:\n    product: linux\ndetection:\n    condition: nothing\n",
            correlation_yaml("level: high\n", &["base_by_name"]),
        ) + BASE_RULES;
        write(dir.path(), "broken_base.yml", &broken_base);
        let no_rules = format!(
            "title: Chain\ncorrelation:\n    type: temporal\n    timespan: 5m\n{BASE_RULES}"
        );
        write(dir.path(), "no_rules.yml", &no_rules);
        let empty_rules = format!(
            "title: Chain\ncorrelation:\n    type: temporal\n    rules: []\n    timespan: 5m\n{BASE_RULES}"
        );
        write(dir.path(), "empty_rules.yml", &empty_rules);
        let bad_level = format!(
            "{}{}",
            correlation_yaml("level: urgent\n", &["base_by_name"]),
            BASE_RULES
        );
        write(dir.path(), "bad_level.yml", &bad_level);
        let bad_status = format!(
            "{}{}",
            correlation_yaml("status: wip\n", &["base_by_name"]),
            BASE_RULES
        );
        write(dir.path(), "bad_status.yml", &bad_status);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.files_seen, 5);
        assert_eq!(set.stats.failed, 5);
        assert!(set.correlations.is_empty());
        assert!(set.rules.is_empty());
    }

    #[test]
    fn correlation_filters_use_the_correlation_meta() {
        let dir = tempdir().unwrap();
        let yaml = format!(
            "{}{}",
            correlation_yaml(
                "status: deprecated\nlevel: low\ntags:\n    - attack.t1190\n",
                &["base_by_name"]
            ),
            BASE_RULES
        );
        write(dir.path(), "chain.yml", &yaml);

        let default = load_rules(dir.path(), &RuleFilters::default());
        assert!(default.correlations.is_empty());
        assert_eq!(default.stats.skipped_status, 1);
        assert_eq!(default.stats.failed, 0);

        let deprecated_ok = load_rules(
            dir.path(),
            &RuleFilters {
                enable_deprecated: true,
                ..Default::default()
            },
        );
        assert_eq!(deprecated_ok.correlations.len(), 1);
        assert_eq!(deprecated_ok.stats.correlations, 1);

        let level = load_rules(
            dir.path(),
            &RuleFilters {
                enable_deprecated: true,
                min_level: "high".to_string(),
                ..Default::default()
            },
        );
        assert!(level.correlations.is_empty());
        // The correlation, plus the two base documents no correlation references, which load as
        // standalone rules and are below `high` too.
        assert_eq!(level.stats.skipped_level, 3);

        let tag = load_rules(
            dir.path(),
            &RuleFilters {
                enable_deprecated: true,
                include_tag: vec!["attack.execution".to_string()],
                ..Default::default()
            },
        );
        assert!(tag.correlations.is_empty());
        // The correlation and the two untagged, unreferenced base documents.
        assert_eq!(tag.stats.skipped_tag, 3);

        let tag_ok = load_rules(
            dir.path(),
            &RuleFilters {
                enable_deprecated: true,
                include_tag: vec!["attack.t1190".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(tag_ok.correlations.len(), 1);
    }

    #[test]
    fn correlation_with_unsupported_base_logsource_is_skipped() {
        let dir = tempdir().unwrap();
        let yaml = format!(
            "{}{}---\ntitle: Windows Base\nname: win\nlogsource:\n    product: windows\n    service: security\ndetection:\n    keywords:\n        - 'x'\n    condition: keywords\n",
            correlation_yaml("level: high\n", &["base_by_name", "win"]),
            BASE_RULES
        );
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 0);
        assert!(set.correlations.is_empty());
        assert_eq!(set.stats.skipped_unsupported_logsource, 1);
        assert_eq!(
            set.stats.skipped_status + set.stats.skipped_level + set.stats.skipped_tag,
            0
        );
    }

    #[test]
    fn two_correlations_may_share_a_base_rule() {
        let dir = tempdir().unwrap();
        let second = "---\ntitle: Second\nlevel: medium\ncorrelation:\n    type: event_count\n    rules: base_by_name\n    group-by: hostname\n    timespan: 60s\n    condition:\n        gte: 3\n";
        let yaml = format!(
            "{}{second}{}",
            correlation_yaml("level: high\n", &["base_by_name", "base-two-id"]),
            BASE_RULES
        );
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 0);
        assert_eq!(set.correlations.len(), 2);
        assert_eq!(set.stats.correlations, 2);
        let first = &set.correlations[0];
        assert_eq!(first.meta.title, "Chain");
        assert_eq!(first.base_rules.len(), 2);
        let second = &set.correlations[1];
        assert_eq!(second.meta.title, "Second");
        assert_eq!(second.base_rules.len(), 1);
        assert_eq!(second.base_rules[0].name(), "base_by_name");
        assert_eq!(second.spec.correlation.rules, vec!["Base One"]);
        assert_eq!(
            second.spec.correlation.group_by.as_deref(),
            Some(&["hostname".to_string()][..])
        );
        // each correlation owns a working copy of the shared base rule
        assert!(first.base_rules[0].rule.is_match(&message_event("one")));
        assert!(second.base_rules[0].rule.is_match(&message_event("one")));
    }

    #[test]
    fn correlation_meta_defaults() {
        let dir = tempdir().unwrap();
        let yaml = format!("{}{}", correlation_yaml("", &["base_by_name"]), BASE_RULES);
        write(dir.path(), "chain.yml", &yaml);
        let set = load_rules(dir.path(), &RuleFilters::default());
        let corr = &set.correlations[0];
        assert_eq!(corr.meta.level, "informational");
        assert_eq!(corr.meta.status, None);
        assert_eq!(corr.meta.modified, None);
        assert!(corr.meta.tags.is_empty());
        assert!(corr.meta.references.is_empty());
        assert!(corr.meta.falsepositives.is_empty());
    }

    // --- helpers -------------------------------------------------------------------------------------

    #[test]
    fn level_rank_and_canonical_level() {
        assert_eq!(level_rank("informational"), 1);
        assert_eq!(level_rank("info"), 1);
        assert_eq!(level_rank("LOW"), 2);
        assert_eq!(level_rank("medium"), 3);
        assert_eq!(level_rank("med"), 3);
        assert_eq!(level_rank("High"), 4);
        assert_eq!(level_rank("critical"), 5);
        assert_eq!(level_rank("crit"), 5);
        assert_eq!(level_rank(""), 0);
        assert_eq!(level_rank("urgent"), 0);

        assert_eq!(canonical_level("INFO"), "informational");
        assert_eq!(canonical_level("Informational"), "informational");
        assert_eq!(canonical_level("low"), "low");
        assert_eq!(canonical_level("Med"), "medium");
        assert_eq!(canonical_level("medium"), "medium");
        assert_eq!(canonical_level("High"), "high");
        assert_eq!(canonical_level("CRIT"), "critical");
        assert_eq!(canonical_level("critical"), "critical");
        assert_eq!(canonical_level("weird"), "weird");
    }

    #[test]
    fn raw_field_key_rewrites() {
        assert_eq!(raw_field_key("|all"), "raw|contains|all");
        assert_eq!(raw_field_key("|contains|all"), "raw|contains|all");
        assert_eq!(raw_field_key("|re"), "raw|re");
        assert_eq!(raw_field_key("|cidr"), "raw|cidr");
        assert_eq!(
            raw_field_key("|base64offset|contains"),
            "raw|base64offset|contains"
        );
        assert_eq!(raw_field_key("|base64"), "raw|base64");
        assert_eq!(raw_field_key(""), "raw|contains");
        assert_eq!(raw_field_key("|"), "raw|contains|");
        assert!(ends_with_unescaped_star("a*"));
        assert!(ends_with_unescaped_star("a\\\\*"));
        assert!(!ends_with_unescaped_star("a\\*"));
        assert!(!ends_with_unescaped_star("a"));
        assert!(!ends_with_unescaped_star(""));
        assert_eq!(trailing_backslashes("a\\\\"), 2);
        assert_eq!(trailing_backslashes("a"), 0);
    }

    const STRAY: &str = "title: Stray\nid: stray\nlogsource: {product: linux, service: syslog}\ndetection:\n  keywords: ['stray']\n  condition: keywords\nlevel: high\n";
    const POST_BASE: &str = "title: Post Base\nname: post_base\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-method: POST\n  condition: sel\nlevel: low\n";

    fn event_count(extra: &str) -> String {
        format!(
            "title: Count\ncorrelation:\n    type: event_count\n    rules: [post_base]\n    timespan: 60s\n{extra}level: medium\n---\n{POST_BASE}"
        )
    }

    #[test]
    fn unknown_correlation_keys_fail_the_file_and_neq_is_kept() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "typo.yml",
            &event_count("    groupby: [c-ip]\n    condition:\n        gte: 2\n"),
        );
        write(
            dir.path(),
            "op.yml",
            &event_count("    condition:\n        ne: 2\n"),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 2);
        assert!(set.correlations.is_empty());

        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "neq.yml",
            &event_count("    condition:\n        neq: 1\n"),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 0);
        assert_eq!(set.correlations.len(), 1);
        assert_eq!(set.correlations[0].condition_neq, Some(1));
    }

    #[test]
    fn invalid_timespan_and_duplicate_names_fail_the_file() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "weeks.yml",
            &event_count("    condition:\n        gte: 2\n")
                .replace("timespan: 60s", "timespan: 1w"),
        );
        write(
            dir.path(),
            "dup.yml",
            &format!(
                "{}---\n{}",
                event_count("    condition:\n        gte: 2\n"),
                POST_BASE.replace("POST", "GET")
            ),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 2);
        assert!(set.correlations.is_empty());
        assert!(set.rules.is_empty());
    }

    #[test]
    fn unreferenced_documents_and_generate_bases_load_as_standalone_rules() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "mixed.yml",
            &format!(
                "{}---\n{STRAY}",
                event_count("    condition:\n        gte: 2\n")
            ),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.correlations.len(), 1);
        assert_eq!(titles(&set), vec!["Stray".to_string()]);

        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "generate.yml",
            &event_count("    generate: true\n    condition:\n        gte: 2\n"),
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.correlations.len(), 1);
        assert_eq!(titles(&set), vec!["Post Base".to_string()]);
    }

    #[test]
    fn a_quantifier_pattern_that_matches_nothing_fails_the_rule() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "typo.yml",
            "title: Typo\nlogsource: {product: linux}\ndetection:\n  selection_a: ['x']\n  condition: all of selectoin_*\nlevel: high\n",
        );
        write(
            dir.path(),
            "ok.yml",
            "title: Ok\nlogsource: {product: linux}\ndetection:\n  selection_a: ['x']\n  filter: ['y']\n  condition: 1 of selection_* and not 1 of filter* and not all of them\nlevel: high\n",
        );
        let set = load_rules(dir.path(), &RuleFilters::default());
        assert_eq!(set.stats.failed, 1);
        assert_eq!(titles(&set), vec!["Ok".to_string()]);
        assert!(glob_match("selection_*", "selection_a"));
        assert!(glob_match("*_a", "selection_a"));
        assert!(glob_match("sel*on*a", "selection_a"));
        assert!(!glob_match("filter*", "selection_a"));
    }

    #[test]
    fn fieldless_all_with_numbers_loads_and_matches() {
        let mut doc: Value = yaml_serde::from_str(
            "title: t\nlogsource: {product: linux}\ndetection:\n  keywords:\n    '|all': [4624, 'inside']\n  condition: keywords\n",
        )
        .unwrap();
        normalize_detection(&mut doc);
        let rule: Rule = yaml_serde::from_value(doc).expect("numeric '|all' values must load");
        let mut ev = Event::new();
        ev.insert("raw", "number 4624 inside");
        assert!(rule.is_match(&ev));
        let mut other = Event::new();
        other.insert("raw", "number 4625 inside");
        assert!(!rule.is_match(&other));
    }
}
