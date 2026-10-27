//! The `dfir-timeline` command: load rules, find inputs, scan, correlate, write, summarize.

use crate::cli::{self, TimelineOptions, offset_to_seconds};
use crate::color::IwatobiColor;
use crate::correlate::{self, BaseHit};
use crate::detect::{ScanOptions, ScanResult, TimeFilter, scan_lines, scan_target};
use crate::errorlog::log_warn;
use crate::input::{self, ScanTarget, SkipReason};
use crate::live;
use crate::logsource::LogSourceSpec;
use crate::output::{
    self, Profile, RenderOptions, Writers, render_correlation, render_detection,
    resolve_output_targets,
};
use crate::parsers::layout::{self, FormatRegistry};
use crate::parsers::{FileFormat, LogFormat, ParseContext};
use crate::rules::{self, RuleFilters, RuleSet};
use crate::summary::{self, Summary};
use crate::util::{self, error_msg, fatal_error, p, p_label, warn_msg};
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressDrawTarget};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Exit status of the command (0 = ok, 1 = usage/runtime error).
pub fn run(opts: &TimelineOptions) -> i32 {
    let no_color = opts.common.no_color;
    crate::errorlog::set_quiet(opts.general.quiet_errors);
    if let Some(n) = opts.general.threads
        && n > 0
        && let Err(e) = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
    {
        log_warn(&format!("Could not set the thread count: {e}"));
    }

    // --- validate inputs -----------------------------------------------------------------
    if let Some(f) = &opts.input.filepath
        && !f.is_file()
    {
        error_msg(
            no_color,
            &format!("File {} does not exist or is not a file.", f.display()),
        );
        return 1;
    }
    if let Some(d) = &opts.input.directory
        && !d.is_dir()
    {
        error_msg(
            no_color,
            &format!(
                "Directory {} does not exist or is not a directory.",
                d.display()
            ),
        );
        return 1;
    }
    if let Some(out) = &opts.output.output
        && !opts.output.clobber
    {
        let existing: Vec<String> = resolve_output_targets(out, &opts.output.output_types)
            .into_iter()
            .filter(|(_, p)| p.exists())
            .map(|(_, p)| p.display().to_string())
            .collect();
        if !existing.is_empty() {
            error_msg(
                no_color,
                &format!(
                    "The output file already exists: {}. Please specify a different filename or add the -C, --clobber option to overwrite.",
                    existing.join(", ")
                ),
            );
            return 1;
        }
    }

    // --- profiles ------------------------------------------------------------------------
    let profiles = match output::parse_profiles(&util::asset(
        "config/profiles.yaml",
        output::DEFAULT_PROFILES,
    )) {
        Ok(p) => p,
        Err(e) => {
            error_msg(
                no_color,
                &format!("Could not read config/profiles.yaml: {e}"),
            );
            return 1;
        }
    };
    let pick = |name: &str| -> Option<Profile> { profiles.get(name).cloned() };
    let (stdout_profile, file_profile) = match &opts.output.profile {
        Some(name) => match pick(name) {
            Some(pr) => (pr.clone(), pr),
            None => {
                error_msg(
                    no_color,
                    &format!(
                        "Profile '{name}' does not exist. Available profiles: {}",
                        profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                );
                return 1;
            }
        },
        None => match (pick("standard"), pick("verbose")) {
            (Some(s), Some(v)) => (s, v),
            _ => {
                error_msg(
                    no_color,
                    "config/profiles.yaml must define the 'standard' and 'verbose' profiles.",
                );
                return 1;
            }
        },
    };

    // --- custom log formats --------------------------------------------------------------
    let custom_formats = match load_custom_formats(opts.input.custom_formats.as_deref()) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error_msg(no_color, &e);
            return 1;
        }
    };
    let forced_format = match &opts.input.log_format {
        None => None,
        Some(name) => match LogFormat::from_name(name)
            .map(FileFormat::Builtin)
            .or_else(|| custom_formats.get(name).map(FileFormat::Layout))
        {
            Some(f) => Some(f),
            None => {
                let names: Vec<String> = custom_formats
                    .formats
                    .iter()
                    .map(|f| f.name.clone())
                    .collect();
                error_msg(no_color, &cli::log_format_error(name, &names));
                return 1;
            }
        },
    };

    // --- rules ---------------------------------------------------------------------------
    let rules_path = if opts.general.rules == Path::new("./rules") {
        util::resolve_default_dir("rules")
    } else {
        opts.general.rules.clone()
    };
    if !rules_path.exists() {
        error_msg(
            no_color,
            &format!(
                "Rule file or directory does not exist: {}",
                rules_path.display()
            ),
        );
        return 1;
    }
    let filters = RuleFilters {
        min_level: opts.filter.min_level.clone(),
        enable_deprecated: opts.filter.enable_deprecated_rules,
        enable_unsupported: opts.filter.enable_unsupported_rules,
        include_status: lower(&opts.filter.include_status),
        exclude_status: lower(&opts.filter.exclude_status),
        include_tag: lower(&opts.filter.include_tag),
        exclude_tag: lower(&opts.filter.exclude_tag),
    };
    let ruleset = rules::load_rules(&rules_path, &filters);
    print_rule_stats(&ruleset, no_color);
    if ruleset.rules.is_empty() && ruleset.correlations.is_empty() {
        error_msg(
            no_color,
            "Iwatobi could not load any rules. Please check the -r, --rules path.",
        );
        return 1;
    }

    // --- time filter ------------------------------------------------------------------------
    let time_filter = match build_time_filter(opts) {
        Ok(f) => f,
        Err(e) => {
            error_msg(no_color, &e);
            return 1;
        }
    };

    // --- inputs ------------------------------------------------------------------------------
    let tz = opts.general.timezone.unwrap_or_default();
    let mut targets: Vec<ScanTarget> = Vec::new();
    let mut hostname_hint = None;
    let mut journal: Option<std::process::Child> = None;
    let mut skipped_logsources: Vec<LogSourceSpec> = Vec::new();
    if opts.input.live_analysis {
        hostname_hint = util::local_hostname();
        let table = match &opts.general.log_locations {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    error_msg(no_color, &format!("Could not read {}: {e}", path.display()));
                    return 1;
                }
            },
            None => util::asset("config/log_locations.yaml", live::DEFAULT_LOG_LOCATIONS),
        };
        let rows = match live::parse_log_locations(&table) {
            Ok(r) => r,
            Err(e) => {
                error_msg(
                    no_color,
                    &format!("Could not parse the log location table: {e}"),
                );
                return 1;
            }
        };
        let needs = needed_logsources(&ruleset);
        let live_opts = live::LiveOptions {
            no_wizard: opts.general.no_wizard,
            no_color,
            since: time_filter.start.map(|s| format!("@{}", s.timestamp())),
        };
        // Say it before any prompt: the answers depend on what this user can read.
        let not_root = cfg!(target_os = "linux") && !live::running_as_root();
        if not_root {
            warn_msg(no_color, live::NOT_ROOT_NOTE);
            log_warn(live::NOT_ROOT_NOTE);
        }
        match live::discover(&needs, &rows, &live_opts, &rules_path) {
            Ok(d) => {
                targets = d.targets;
                journal = d.journal;
                skipped_logsources = d.skipped;
                for note in d
                    .notes
                    .iter()
                    .filter(|n| !(not_root && n.as_str() == live::NOT_ROOT_NOTE))
                {
                    warn_msg(no_color, note);
                    log_warn(note);
                }
            }
            Err(e) => {
                error_msg(no_color, &e);
                return 1;
            }
        }
        for t in &mut targets {
            t.format = t.format.clone().or_else(|| forced_format.clone());
        }
        if !skipped_logsources.is_empty() {
            let names: Vec<String> = skipped_logsources
                .iter()
                .map(|s| format!("{{{s}}}"))
                .collect();
            warn_msg(
                no_color,
                &format!(
                    "No log files were found for {} log source(s); the rules that need them were skipped: {}",
                    skipped_logsources.len(),
                    names.join(", ")
                ),
            );
        }
    } else if let Some(f) = &opts.input.filepath {
        targets = input::enumerate(f, forced_format.clone());
    } else if let Some(d) = &opts.input.directory {
        targets = input::enumerate(d, forced_format.clone());
    }
    if let Some(out) = &opts.output.output {
        let outputs: Vec<std::path::PathBuf> =
            resolve_output_targets(out, &opts.output.output_types)
                .into_iter()
                .map(|(_, p)| absolute(&p))
                .collect();
        if opts.input.filepath.is_some()
            && targets.iter().any(|t| outputs.contains(&absolute(&t.path)))
        {
            error_msg(
                no_color,
                "The output file is the input file. Please choose a different output file.",
            );
            return 1;
        }
        targets.retain(|t| {
            let keep = !outputs.contains(&absolute(&t.path));
            if !keep {
                log_warn(&format!(
                    "Not scanning the output file {}",
                    t.path.display()
                ));
            }
            keep
        });
    }
    if targets.is_empty() && journal.is_none() {
        error_msg(no_color, "No log files to scan.");
        return 1;
    }

    // --- writers -------------------------------------------------------------------------------
    let writers = match Writers::new(
        opts.output.output.as_deref(),
        &opts.output.output_types,
        &stdout_profile,
        &file_profile,
        no_color,
        opts.output.sort,
    ) {
        Ok(w) => w,
        Err(e) => fatal_error(no_color, &e),
    };
    let render_profile = if writers.writes_stdout() {
        stdout_profile.clone()
    } else {
        file_profile.clone()
    };
    let render_opts = RenderOptions {
        utc: opts.output.utc,
    };

    // Only the live rules that have a log to run against matter for the summary of needs.
    let ruleset = if skipped_logsources.is_empty() {
        ruleset
    } else {
        drop_rules_for(ruleset, &skipped_logsources)
    };

    if !custom_formats.is_empty() {
        p_label(
            no_color,
            "Custom log formats: ",
            &util::fmt_num(custom_formats.formats.len()),
        );
    }
    p_label(
        no_color,
        "Total log files: ",
        &util::fmt_num(targets.len() + usize::from(journal.is_some())),
    );
    util::p(None, "", true);
    p_label(no_color, "Output profile: ", &render_profile.name);
    util::p(None, "", true);

    // --- scan ------------------------------------------------------------------------------------
    let scan_opts = ScanOptions {
        tz,
        hostname_hint,
        time_filter,
        custom_formats,
    };
    let state = Arc::new(Mutex::new(ScanState {
        writers,
        summary: Summary::default(),
        base_hits: Vec::new(),
        mixed_zone_files: 0,
        unrecognized_files: 0,
        auto_layouts: BTreeMap::new(),
    }));
    let verbose = opts.general.verbose;
    let single_file = opts.input.filepath.is_some();
    let ruleset_ref = &ruleset;
    let profile_ref = &render_profile;
    let opts_ref = &render_opts;
    // Like Hayabusa, the progress bar is shown only when the results are saved to a file: rows
    // streamed to the terminal and a redrawing bar would overwrite each other.
    let saving_to_file = !state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .writers
        .writes_stdout();
    let bar = saving_to_file.then(|| {
        p(
            IwatobiColor::Orange.rdg(no_color),
            "Scanning in progress. Please wait.",
            true,
        );
        util::p(None, "", true);
        progress_bar(targets.len() + usize::from(journal.is_some()), no_color)
    });
    targets.par_iter().for_each(|target| {
        if let Some(b) = &bar {
            b.set_message(progress_message(&target.path));
        }
        let result = scan_target(target, ruleset_ref, &scan_opts);
        with_bar_suspended(&bar, || {
            report_file(target, &result, verbose || single_file, no_color)
        });
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        consume_result(&mut st, result, ruleset_ref, profile_ref, opts_ref);
        if let Some(b) = &bar {
            b.inc(1);
        }
    });
    if let Some(mut child) = journal.take() {
        let target = ScanTarget {
            path: std::path::PathBuf::from("journalctl"),
            display_name: "journalctl".to_string(),
            extra_tags: Vec::new(),
            format: Some(LogFormat::Syslog.into()),
        };
        // Drain stderr on its own thread: a journalctl that writes more than the pipe buffer
        // would otherwise block, and the "not seeing messages" hint is how a partial (non-root)
        // read of the journal shows up.
        let stderr_reader = child.stderr.take().map(|stderr| {
            std::thread::spawn(move || {
                input::Lines::new(stderr)
                    .map_while(Result::ok)
                    .collect::<Vec<String>>()
            })
        });
        if let Some(b) = &bar {
            b.set_message("journalctl");
        }
        if let Some(stdout) = child.stdout.take() {
            let mut ctx = ParseContext::new(Path::new("."), tz);
            ctx.display_name = "journalctl".to_string();
            ctx.hostname_hint = scan_opts.hostname_hint.clone();
            ctx.year_hint = Utc::now().format("%Y").to_string().parse().unwrap_or(2000);
            let mut result = ScanResult {
                format: Some(LogFormat::Syslog.into()),
                ..Default::default()
            };
            // Lossy UTF-8 like the file reader: one odd byte must not end the journal.
            scan_lines(
                input::Lines::new(stdout).map_while(Result::ok),
                &LogFormat::Syslog.into(),
                ctx,
                &target,
                ruleset_ref,
                &scan_opts,
                &mut result,
            );
            with_bar_suspended(&bar, || report_file(&target, &result, verbose, no_color));
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            consume_result(&mut st, result, ruleset_ref, profile_ref, opts_ref);
        }
        if let Some(b) = &bar {
            b.inc(1);
        }
        let stderr_lines = stderr_reader
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        let mut partial = false;
        for line in &stderr_lines {
            log_warn(&format!("journalctl: {line}"));
            if line.contains("not seeing messages") || line.contains("insufficient permissions") {
                partial = true;
            }
        }
        if partial {
            let msg = "journalctl could not read the system journal completely (run as root or as a member of systemd-journal); results may be incomplete";
            log_warn(msg);
            with_bar_suspended(&bar, || warn_msg(no_color, msg));
        }
        match child.wait() {
            Ok(status) if !status.success() => {
                let msg = format!("journalctl exited with {status}; the journal may be incomplete");
                log_warn(&msg);
                with_bar_suspended(&bar, || warn_msg(no_color, &msg));
            }
            Err(e) => log_warn(&format!("journalctl: {e}")),
            _ => {}
        }
    }
    if let Some(b) = &bar {
        b.finish_with_message(finished_message(no_color));
    }

    let mut st = match Arc::try_unwrap(state) {
        Ok(m) => m.into_inner().unwrap_or_else(|e| e.into_inner()),
        Err(arc) => {
            let mut g = arc.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *g, ScanState::empty())
        }
    };

    // --- correlation -----------------------------------------------------------------------------
    if !ruleset.correlations.is_empty() && !st.base_hits.is_empty() {
        let outcome = correlate::evaluate(&ruleset.correlations, &st.base_hits);
        st.summary.correlation_hits_skipped = outcome.skipped_missing_group_by;
        for hit in &outcome.hits {
            let corr = &ruleset.correlations[hit.correlation_index];
            if rules::level_rank(&corr.meta.level) < rules::level_rank(&filters.min_level) {
                continue;
            }
            let members: Vec<&BaseHit> = hit.members.iter().map(|i| &st.base_hits[*i]).collect();
            let row = render_correlation(hit, &members, &corr.meta, &render_profile, &render_opts);
            let date = output::format_timestamp(&hit.timestamp, render_opts.utc);
            st.summary.record(
                &corr.meta.level,
                &corr.meta.title,
                corr.meta.author.as_deref(),
                Some(&date[..10.min(date.len())]),
            );
            st.summary.see_time(hit.timestamp);
            st.writers.write(row);
        }
    }
    if let Err(e) = st.writers.finish() {
        fatal_error(no_color, &e);
    }
    report_formats(&st, no_color);
    if st.mixed_zone_files > 0 && opts.general.timezone.is_none() {
        let msg = "Some logs carry a timezone and others do not; timestamps without one were read as local time. Use -z (ex: -z UTC) if those logs come from another timezone.";
        warn_msg(no_color, msg);
        log_warn(msg);
    }

    // --- summary --------------------------------------------------------------------------------
    util::p(None, "", true);
    if !opts.output.no_summary {
        summary::print_summary(&st.summary, no_color, opts.output.utc);
    }
    let single_file_unread = opts.input.filepath.is_some() && st.summary.files_scanned == 0;
    if !st.writers.paths.is_empty() {
        p(IwatobiColor::Green.rdg(no_color), "Results saved: ", false);
        let parts: Vec<String> = st
            .writers
            .paths
            .iter()
            .map(|pth| format!("{} ({})", pth.display(), util::file_size_display(pth)))
            .collect();
        p(None, &parts.join(" and "), true);
    }
    i32::from(single_file_unread)
}

struct ScanState {
    writers: Writers,
    summary: Summary,
    base_hits: Vec<BaseHit>,
    mixed_zone_files: usize,
    /// Files skipped because no format matched them.
    unrecognized_files: usize,
    /// Automatically detected access log layout (as an nginx `log_format`) → files.
    auto_layouts: BTreeMap<String, usize>,
}

impl ScanState {
    fn empty() -> Self {
        Self {
            writers: Writers::empty(),
            summary: Summary::default(),
            base_hits: Vec::new(),
            mixed_zone_files: 0,
            unrecognized_files: 0,
            auto_layouts: BTreeMap::new(),
        }
    }
}

fn consume_result(
    st: &mut ScanState,
    mut result: ScanResult,
    ruleset: &RuleSet,
    profile: &Profile,
    opts: &RenderOptions,
) {
    for det in result.detections.drain(..) {
        let meta = &ruleset.rules[det.rule_index].meta;
        let row = render_detection(&det, meta, profile, opts);
        let date = det
            .event
            .timestamp
            .map(|t| output::format_timestamp(&t.with_timezone(&Utc), opts.utc))
            .map(|s| s[..10.min(s.len())].to_string());
        result.summary.record(
            &meta.level,
            &meta.title,
            meta.author.as_deref(),
            date.as_deref(),
        );
        st.writers.write(row);
    }
    st.base_hits.append(&mut result.base_hits);
    if result.skipped == Some(SkipReason::UnrecognizedFormat) {
        st.unrecognized_files += 1;
    }
    if let Some(l) = result.format.as_ref().and_then(FileFormat::auto_layout) {
        *st.auto_layouts.entry(l.display.clone()).or_default() += 1;
    }
    if result.mixed_zone_sources {
        st.mixed_zone_files += 1;
    }
    st.summary.merge(result.summary);
}

/// The custom log formats: `--custom-formats FILE`, or `config/custom_log_formats.yaml`.
fn load_custom_formats(path: Option<&Path>) -> Result<FormatRegistry, String> {
    let (text, name) = match path {
        Some(p) => (
            std::fs::read_to_string(p).map_err(|e| {
                format!("Could not read the custom log formats {}: {e}", p.display())
            })?,
            p.display().to_string(),
        ),
        None => (
            util::asset(
                "config/custom_log_formats.yaml",
                layout::DEFAULT_CUSTOM_FORMATS,
            ),
            "config/custom_log_formats.yaml".to_string(),
        ),
    };
    FormatRegistry::parse(&text).map_err(|e| format!("{name}: {e}"))
}

/// After the scan: the access log layouts that were detected automatically (so that a wrong
/// guess can be seen and corrected) and the files whose format was not recognized.
fn report_formats(st: &ScanState, no_color: bool) {
    for (display, files) in &st.auto_layouts {
        util::p(None, "", true);
        p_label(
            no_color,
            "Access log layout detected automatically: ",
            &format!(
                "{} file{}",
                util::fmt_num(*files),
                if *files == 1 { "" } else { "s" }
            ),
        );
        p(None, &format!("    {display}"), true);
        let msg = format!("Access log layout detected automatically ({files} files): {display}");
        log_warn(&msg);
    }
    if !st.auto_layouts.is_empty() {
        p(
            None,
            "If a field is wrong, add the layout to config/custom_log_formats.yaml as an nginx format and correct it (see \"Custom log formats\" in the README).",
            true,
        );
    }
    if st.unrecognized_files > 0 {
        util::p(None, "", true);
        let n = st.unrecognized_files;
        warn_msg(
            no_color,
            &format!(
                "{} file{} skipped because the log format was not recognized (-v lists them). To scan {}, describe the format in config/custom_log_formats.yaml (see \"Custom log formats\" in the README).",
                util::fmt_num(n),
                if n == 1 { " was" } else { "s were" },
                if n == 1 { "it" } else { "them" },
            ),
        );
    }
}

fn report_file(target: &ScanTarget, result: &ScanResult, verbose: bool, no_color: bool) {
    if let Some(reason) = &result.skipped {
        let msg = format!("Skipped {}: {reason}", target.display_name);
        log_warn(&msg);
        if verbose {
            error_msg(no_color, &msg);
        }
    } else if let Some(err) = &result.read_error {
        let msg = format!(
            "{}: {err}; only the lines before the error were scanned",
            target.display_name
        );
        log_warn(&msg);
        warn_msg(no_color, &msg);
    } else if verbose {
        let fmt = result
            .format
            .as_ref()
            .map_or_else(|| "-".to_string(), FileFormat::name);
        p(
            None,
            &format!(
                "Scanned {} ({fmt}, {} events, {} detections)",
                target.display_name,
                result.events,
                result.detections.len()
            ),
            true,
        );
    }
}

/// Hayabusa's scan progress bar: elapsed time, files done / total, a green spinner and bar, the
/// percentage, and the file being scanned on the line below. It draws only on a terminal.
fn progress_bar(len: usize, no_color: bool) -> ProgressBar {
    let bar =
        ProgressBar::with_draw_target(Some(len as u64), ProgressDrawTarget::stdout_with_hz(10))
            .with_tab_width(55);
    bar.set_style(
        indicatif::ProgressStyle::with_template(&progress_template(no_color))
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar())
            .progress_chars("=> "),
    );
    bar.enable_steady_tick(Duration::from_millis(300));
    bar
}

fn progress_template(no_color: bool) -> String {
    let green = |s: &str| {
        if no_color {
            s.to_string()
        } else {
            format!("\x1b[38;2;0;255;0m{s}\x1b[0m")
        }
    };
    format!(
        "[{{elapsed_precise}}] {{human_pos}} / {{human_len}} {} [{}] {{percent}}%\n\n{{msg}}",
        green("{spinner}"),
        green("{bar:40}")
    )
}

/// The file being scanned, quoted, with its size: `"/var/log/apache2/error.log" (1.2 MiB)`.
fn progress_message(path: &Path) -> String {
    format!(
        "{:?} ({})",
        path.to_string_lossy().replace('\\', "/"),
        util::file_size_display(path)
    )
}

fn finished_message(no_color: bool) -> String {
    let msg = "Scanning finished. Please wait while the results are being saved.\n";
    if no_color {
        msg.to_string()
    } else {
        format!("\x1b[38;5;214m{msg}\x1b[0m")
    }
}

/// Runs `f` with the progress bar cleared, so a message printed while scanning does not tear it.
fn with_bar_suspended<R>(bar: &Option<ProgressBar>, f: impl FnOnce() -> R) -> R {
    match bar {
        Some(b) => b.suspend(f),
        None => f(),
    }
}

/// An absolute path for comparisons: canonical when the file exists, otherwise the canonical
/// parent joined with the file name.
fn absolute(path: &Path) -> std::path::PathBuf {
    if let Ok(p) = std::fs::canonicalize(path) {
        return p;
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match (std::fs::canonicalize(parent), path.file_name()) {
        (Ok(dir), Some(name)) => dir.join(name),
        _ => path.to_path_buf(),
    }
}

fn lower(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn build_time_filter(opts: &TimelineOptions) -> Result<TimeFilter, String> {
    let mut f = TimeFilter::default();
    if let Some(s) = &opts.filter.timeline_start {
        f.start = Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc),
        );
    }
    if let Some(e) = &opts.filter.timeline_end {
        f.end = Some(
            DateTime::parse_from_rfc3339(e)
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc),
        );
    }
    if let Some(off) = &opts.filter.time_offset {
        let secs = offset_to_seconds(off).ok_or_else(|| format!("invalid time offset {off}"))?;
        f.start = chrono::TimeDelta::try_seconds(secs)
            .and_then(|d| Utc::now().checked_sub_signed(d))
            .or(Some(DateTime::<Utc>::MIN_UTC));
    }
    if let (Some(s), Some(e)) = (f.start, f.end)
        && s > e
    {
        return Err("--timeline-start is after --timeline-end".to_string());
    }
    Ok(f)
}

/// The distinct logsources of every loaded rule (detection and correlation base rules).
pub fn needed_logsources(ruleset: &RuleSet) -> Vec<LogSourceSpec> {
    let mut seen = BTreeMap::new();
    for r in &ruleset.rules {
        seen.entry(r.logsource.to_string())
            .or_insert_with(|| r.logsource.clone());
    }
    for c in &ruleset.correlations {
        for b in &c.base_rules {
            seen.entry(b.logsource.to_string())
                .or_insert_with(|| b.logsource.clone());
        }
    }
    seen.into_values().collect()
}

/// Drop the rules whose logsource the user chose to skip in live analysis.
fn drop_rules_for(ruleset: RuleSet, skipped: &[LogSourceSpec]) -> RuleSet {
    let RuleSet {
        rules,
        correlations,
        stats,
    } = ruleset;
    let rules = rules
        .into_iter()
        .filter(|r| !skipped.contains(&r.logsource))
        .collect();
    let correlations = correlations
        .into_iter()
        .filter(|c| !c.base_rules.iter().any(|b| skipped.contains(&b.logsource)))
        .collect();
    RuleSet {
        rules,
        correlations,
        stats,
    }
}

fn print_rule_stats(ruleset: &RuleSet, no_color: bool) {
    let s = &ruleset.stats;
    p_label(
        no_color,
        "Total detection rules: ",
        &util::fmt_num(ruleset.rules.len()),
    );
    p_label(
        no_color,
        "Total correlation rules: ",
        &util::fmt_num(ruleset.correlations.len()),
    );
    if s.skipped_unsupported_logsource > 0 {
        p_label(
            no_color,
            "Rules skipped (unsupported log source): ",
            &util::fmt_num(s.skipped_unsupported_logsource),
        );
    }
    if s.skipped_status > 0 {
        p_label(
            no_color,
            "Rules skipped (status): ",
            &util::fmt_num(s.skipped_status),
        );
    }
    if s.skipped_level > 0 {
        p_label(
            no_color,
            "Rules skipped (below minimum level): ",
            &util::fmt_num(s.skipped_level),
        );
    }
    if s.skipped_tag > 0 {
        p_label(
            no_color,
            "Rules skipped (tags): ",
            &util::fmt_num(s.skipped_tag),
        );
    }
    if s.failed > 0 {
        p_label(
            no_color,
            "Rules failed to load (see the error log): ",
            &util::fmt_num(s.failed),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_template_is_hayabusas_with_a_green_spinner_and_bar() {
        assert_eq!(
            progress_template(true),
            "[{elapsed_precise}] {human_pos} / {human_len} {spinner} [{bar:40}] {percent}%\n\n{msg}"
        );
        assert_eq!(
            progress_template(false),
            "[{elapsed_precise}] {human_pos} / {human_len} \x1b[38;2;0;255;0m{spinner}\x1b[0m [\x1b[38;2;0;255;0m{bar:40}\x1b[0m] {percent}%\n\n{msg}"
        );
        for no_color in [true, false] {
            assert!(indicatif::ProgressStyle::with_template(&progress_template(no_color)).is_ok());
        }
    }

    #[test]
    fn progress_message_quotes_the_path_and_shows_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        std::fs::write(&log, vec![b'a'; 2048]).unwrap();
        assert_eq!(
            progress_message(&log),
            format!(
                "\"{}\" (2.0 KiB)",
                log.display().to_string().replace('\\', "/")
            )
        );
        assert_eq!(
            progress_message(Path::new("logs\\gone.log")),
            "\"logs/gone.log\" (-)"
        );
        // control characters in a file name are escaped, not sent to the terminal
        assert_eq!(
            progress_message(Path::new("a\x1b[2Jb")),
            "\"a\\u{1b}[2Jb\" (-)"
        );
    }

    #[test]
    fn finished_message_is_orange_unless_colors_are_disabled() {
        let plain = "Scanning finished. Please wait while the results are being saved.\n";
        assert_eq!(finished_message(true), plain);
        assert_eq!(
            finished_message(false),
            format!("\x1b[38;5;214m{plain}\x1b[0m")
        );
    }
}
