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

//! Live analysis (`-l`): find the local log files the loaded rules need (design §7, amendment A14).
//!
//! The flow of [`discover`]:
//! 1. warn when the effective uid is not 0 (most of `/var/log` is `root:adm 0640`);
//! 2. expand the glob patterns of the location-table row of every needed logsource and build ONE
//!    [`ScanTarget`] per canonical file (rows never attach tags: the parsers tag events by file
//!    name and process name);
//! 3. when no syslog-family file was found, at least one rule needs `product: linux` and
//!    `journalctl` is on `PATH`, export the systemd journal (asked first when the wizard runs).
//!    The journal is a syslog-family source, so it satisfies every `product: linux` need and
//!    their rules are kept;
//! 4. for every need that still has no file: ask for a directory or file (wizard) or skip the
//!    rules that need it. A path the user enters gets the needed logsource as `extra_tags`.
//!
//! Nothing is printed here; the caller shows `notes` and drops the rules of `skipped`.

use crate::input::{self, ScanTarget};
use crate::logsource::{LogSourceSpec, LogSourceTag, SUPPORTED_TAGS};
use crate::parsers::{self, LogFormat};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Embedded default location table.
pub const DEFAULT_LOG_LOCATIONS: &str = include_str!("../config/log_locations.yaml");

/// Shown (once) when the effective uid is not 0.
pub const NOT_ROOT_NOTE: &str = "Live analysis needs root or membership in the adm / systemd-journal groups to read every log; results may be incomplete.";
/// Shown when the wizard was not disabled but cannot run (amendment A14).
pub const NON_TTY_NOTE: &str = "stdin or stdout is not a terminal: running without the wizard (rules whose logs were not found are skipped).";
/// Shown when the systemd journal is exported.
pub const JOURNAL_NOTE: &str = "Reading the systemd journal with journalctl";
const JOURNAL_PROMPT: &str = "Export the systemd journal with journalctl and scan it?";
const PATH_PROMPT: &str = "Directory or file to scan";
const SELECT_ENTER: &str = "Enter a directory or file to scan";
const SELECT_SKIP: &str = "Skip these rules";
/// How many times the path prompt is repeated for a path that does not exist.
const PATH_ATTEMPTS: usize = 3;

/// One row of `config/log_locations.yaml`.
#[derive(Clone, Debug)]
pub struct LocationRow {
    pub logsource: LogSourceSpec,
    pub patterns: Vec<String>,
}

#[derive(Deserialize)]
struct RawRow {
    logsource: RawLogSource,
    paths: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawLogSource {
    product: Option<String>,
    category: Option<String>,
    service: Option<String>,
}

/// Parse the location table: a sequence of `{logsource: {product?, category?, service?},
/// paths: [globs]}` entries. A table with no entries (comments only) is valid and empty.
pub fn parse_log_locations(yaml: &str) -> Result<Vec<LocationRow>, String> {
    let rows: Option<Vec<RawRow>> = yaml_serde::from_str(yaml).map_err(|e| e.to_string())?;
    Ok(rows
        .unwrap_or_default()
        .into_iter()
        .map(|row| LocationRow {
            logsource: LogSourceSpec::new(
                row.logsource.product.as_deref(),
                row.logsource.category.as_deref(),
                row.logsource.service.as_deref(),
            ),
            patterns: row
                .paths
                .into_iter()
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
        })
        .collect())
}

#[derive(Clone, Debug, Default)]
pub struct LiveOptions {
    pub no_wizard: bool,
    pub no_color: bool,
    /// `--since` for journalctl, when a time filter was given.
    pub since: Option<String>,
}

/// The result of live discovery.
#[derive(Debug, Default)]
pub struct LiveDiscovery {
    pub targets: Vec<ScanTarget>,
    /// Logsources needed by rules for which no file was found (and the user skipped them).
    pub skipped: Vec<LogSourceSpec>,
    /// A running `journalctl` export to read as syslog, when used.
    pub journal: Option<std::process::Child>,
    /// Human-readable notes for the terminal (permission warnings, partial journal, ...).
    pub notes: Vec<String>,
}

/// Find the files for `needs` (the distinct logsources of the loaded rules), prompting when
/// allowed. Returns an error only when live analysis is impossible on this platform.
pub fn discover(
    needs: &[LogSourceSpec],
    rows: &[LocationRow],
    opts: &LiveOptions,
    rules_dir_for_prompt: &Path,
) -> Result<LiveDiscovery, String> {
    // The prompt texts are fixed by the design; the rules directory is not part of them.
    let _ = rules_dir_for_prompt;
    if !cfg!(target_os = "linux") {
        return Err("live analysis is only supported on Linux".to_string());
    }
    Ok(discover_with(needs, rows, opts, &Environment::detect()))
}

/// The facts about the machine that drive the discovery, separated from [`discover`] so the
/// tests can fake them.
#[derive(Clone, Debug)]
struct Environment {
    /// The effective uid is 0.
    is_root: bool,
    /// Both stdin and stdout are terminals, so the dialoguer prompts can run.
    interactive: bool,
    /// The `PATH` searched for `journalctl`.
    path_var: OsString,
}

impl Environment {
    fn detect() -> Self {
        Self {
            is_root: effective_uid_is_root(),
            // dialoguer reads stdin and draws its prompts on stderr.
            interactive: std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
            path_var: std::env::var_os("PATH").unwrap_or_default(),
        }
    }
}

fn discover_with(
    needs: &[LogSourceSpec],
    rows: &[LocationRow],
    opts: &LiveOptions,
    env: &Environment,
) -> LiveDiscovery {
    let mut notes = Notes::default();
    if !env.is_root {
        notes.push(NOT_ROOT_NOTE);
    }
    let wizard = !opts.no_wizard && env.interactive;
    if !opts.no_wizard && !env.interactive {
        notes.push(NON_TTY_NOTE);
    }

    // Expand the rows of every need; one target per canonical file.
    let mut found = TargetSet::default();
    let mut outcomes: Vec<(&LogSourceSpec, NeedOutcome)> = Vec::with_capacity(needs.len());
    for need in needs {
        let patterns: Vec<&str> = rows
            .iter()
            .filter(|row| row.logsource == *need)
            .flat_map(|row| row.patterns.iter().map(String::as_str))
            .collect();
        let outcome = expand_patterns(&patterns, &mut found, &mut notes);
        outcomes.push((need, outcome));
    }
    found.sort();
    // A rule without a logsource applies to every event, so any file at all satisfies it.
    let any_file = !found.is_empty();
    let mut unresolved: Vec<&LogSourceSpec> = outcomes
        .into_iter()
        .filter(|(need, outcome)| {
            *outcome == NeedOutcome::NotFound && !(need.is_empty() && any_file)
        })
        .map(|(need, _)| need)
        .collect();

    // The systemd journal replaces the syslog-family files when none was found.
    let mut journal = None;
    if journal_wanted(needs, found.targets())
        && let Some(exe) = find_journalctl(&env.path_var)
    {
        let wanted = !wizard || confirm_journal(opts.no_color);
        if wanted {
            match spawn_journalctl(&exe, opts.since.as_deref()) {
                Ok(child) => {
                    journal = Some(child);
                    notes.push(JOURNAL_NOTE);
                    // The journal satisfies every syslog-family need: keep their rules.
                    unresolved.retain(|need| !is_linux(need));
                }
                Err(e) => notes.push(format!("Could not run journalctl ({}): {e}", exe.display())),
            }
        }
    }

    // Prompt for (or skip) every need that still has no file.
    let mut skipped = Vec::new();
    let mut asked: HashSet<&LogSourceSpec> = HashSet::new();
    for need in unresolved {
        if !asked.insert(need) {
            continue;
        }
        let entered = if wizard {
            prompt_for_path(opts.no_color, need)
        } else {
            None
        };
        match entered {
            Some(path) => {
                add_user_path(&path, need, &mut found);
            }
            None => skipped.push(need.clone()),
        }
    }

    LiveDiscovery {
        targets: found.into_targets(),
        skipped,
        journal,
        notes: notes.list,
    }
}

/// What expanding the patterns of one need produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NeedOutcome {
    /// At least one readable regular file.
    Found,
    /// No file exists (or the need has no row): prompt or skip.
    NotFound,
    /// A file or directory exists but cannot be read: reported, never prompted for.
    PermissionProblem,
}

/// Expand every pattern and add the readable regular files to `found`.
fn expand_patterns(patterns: &[&str], found: &mut TargetSet, notes: &mut Notes) -> NeedOutcome {
    let mut files = 0usize;
    let mut permission_problem = false;
    for pattern in patterns {
        let paths = match glob::glob(pattern) {
            Ok(paths) => paths,
            Err(e) => {
                notes.push(format!(
                    "Invalid glob pattern '{pattern}' in the log location table: {e}"
                ));
                continue;
            }
        };
        for entry in paths {
            match entry {
                Ok(path) => {
                    if !path.is_file() {
                        continue;
                    }
                    match std::fs::File::open(&path) {
                        Ok(_) => {
                            found.add(&path, None);
                            files += 1;
                        }
                        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                            notes.push(format!("permission denied: {}", path.display()));
                            permission_problem = true;
                        }
                        Err(e) => {
                            notes.push(format!("Could not open {}: {e}", path.display()));
                        }
                    }
                }
                Err(e) if e.error().kind() == ErrorKind::PermissionDenied => {
                    notes.push(format!(
                        "permission denied: {} (cannot list the directory)",
                        e.path().display()
                    ));
                    permission_problem = true;
                }
                Err(e) => {
                    notes.push(format!(
                        "Could not read {}: {}",
                        e.path().display(),
                        e.error()
                    ));
                }
            }
        }
    }
    if files > 0 {
        NeedOutcome::Found
    } else if permission_problem {
        NeedOutcome::PermissionProblem
    } else {
        NeedOutcome::NotFound
    }
}

/// The scan targets, one per canonical file, in the order they were found.
#[derive(Default)]
struct TargetSet {
    /// `(canonical path, target)`; the target keeps the path the pattern matched (so the file
    /// name hints and the `LogFile` column show the path the user knows).
    entries: Vec<(PathBuf, ScanTarget)>,
}

impl TargetSet {
    /// Add a file (with an optional extra tag). A file already present only gains the tag.
    /// Returns true when the file was new.
    fn add(&mut self, path: &Path, tag: Option<LogSourceTag>) -> bool {
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if let Some((_, target)) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            if let Some(tag) = tag
                && !target.extra_tags.contains(&tag)
            {
                target.extra_tags.push(tag);
            }
            return false;
        }
        let mut target = ScanTarget::new(path);
        target.extra_tags.extend(tag);
        self.entries.push((key, target));
        true
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn targets(&self) -> impl Iterator<Item = &ScanTarget> {
        self.entries.iter().map(|(_, t)| t)
    }

    fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.1.path.cmp(&b.1.path));
    }

    fn into_targets(self) -> Vec<ScanTarget> {
        self.entries.into_iter().map(|(_, t)| t).collect()
    }
}

/// Notes for the terminal, without exact duplicates (several patterns of several needs hit the
/// same unreadable directory).
#[derive(Default)]
struct Notes {
    list: Vec<String>,
    seen: HashSet<String>,
}

impl Notes {
    fn push(&mut self, note: impl Into<String>) {
        let note = note.into();
        if self.seen.insert(note.clone()) {
            self.list.push(note);
        }
    }
}

/// A need the syslog files or the systemd journal can satisfy: `product: linux`, except the audit
/// records, which are only in `/var/log/audit`.
fn is_linux(need: &LogSourceSpec) -> bool {
    need.product.as_deref() == Some("linux") && need.service.as_deref() != Some("auditd")
}

/// True when the systemd journal should replace the syslog-family files: a rule needs
/// `product: linux` and no found file is a syslog-family log by name.
fn journal_wanted<'a>(
    needs: &[LogSourceSpec],
    targets: impl IntoIterator<Item = &'a ScanTarget>,
) -> bool {
    needs.iter().any(is_linux)
        && !targets
            .into_iter()
            .any(|t| parsers::path_hints(&t.path).format == Some(LogFormat::Syslog))
}

/// The first supported tag the need matches: the tag given to the events of a path the user
/// entered for that need.
fn extra_tag_for(need: &LogSourceSpec) -> Option<LogSourceTag> {
    SUPPORTED_TAGS
        .iter()
        .find(|tag| need.matches_tag(tag))
        .copied()
}

/// Add a path the user entered for `need`: the file, or every regular file under the directory.
/// Returns the number of new targets.
fn add_user_path(path: &Path, need: &LogSourceSpec, found: &mut TargetSet) -> usize {
    let tag = extra_tag_for(need);
    input::enumerate(path, None)
        .iter()
        .filter(|target| found.add(&target.path, tag))
        .count()
}

/// Look for an executable `journalctl` in the directories of a `PATH` value.
pub fn find_journalctl(path_var: impl AsRef<OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path_var.as_ref())
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join("journalctl"))
        .find(|candidate| is_executable_file(candidate))
}

/// Start `journalctl --system --no-pager -o short-iso-precise [--since <since>]` with stdout and
/// stderr piped. The caller reads stdout and waits; nothing is read here.
pub fn spawn_journalctl(exe: &Path, since: Option<&str>) -> std::io::Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.args(["--system", "--no-pager", "-o", "short-iso-precise"]);
    if let Some(since) = since.map(str::trim).filter(|s| !s.is_empty()) {
        cmd.arg("--since").arg(since);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // ETXTBSY: the executable was just written (a package upgrade, or a test's fake journalctl
    // whose write handle a concurrently forked child still holds), so retry briefly.
    let mut attempts = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.kind() == ErrorKind::ExecutableFileBusy && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            res => return res,
        }
    }
}

/// Whether live analysis runs with the effective uid 0 (always false off Unix).
pub fn running_as_root() -> bool {
    effective_uid_is_root()
}

#[cfg(unix)]
fn effective_uid_is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    // `/proc/self` resolves to the process's own directory, owned by its effective uid.
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn effective_uid_is_root() -> bool {
    false
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn prompt_theme(no_color: bool) -> Box<dyn dialoguer::theme::Theme> {
    if no_color {
        Box::new(dialoguer::theme::SimpleTheme)
    } else {
        Box::new(dialoguer::theme::ColorfulTheme::default())
    }
}

/// Ask whether to export the journal; any prompt error means "no".
fn confirm_journal(no_color: bool) -> bool {
    let theme = prompt_theme(no_color);
    dialoguer::Confirm::with_theme(&*theme)
        .with_prompt(JOURNAL_PROMPT)
        .default(true)
        .interact()
        .unwrap_or(false)
}

/// Ask for a directory or file for a need without logs. `None` means skip (chosen, prompt
/// error, or no existing path after [`PATH_ATTEMPTS`] tries).
fn prompt_for_path(no_color: bool, need: &LogSourceSpec) -> Option<PathBuf> {
    let theme = prompt_theme(no_color);
    let choice = dialoguer::Select::with_theme(&*theme)
        .with_prompt(format!(
            "No log files were found for rules with logsource {{{need}}}"
        ))
        .items([SELECT_ENTER, SELECT_SKIP])
        .default(0)
        .interact();
    if !matches!(choice, Ok(0)) {
        return None;
    }
    let mut prompt = PATH_PROMPT.to_string();
    for attempt in 1..=PATH_ATTEMPTS {
        let entered = dialoguer::Input::<String>::with_theme(&*theme)
            .with_prompt(prompt.as_str())
            .interact_text()
            .ok()?;
        let entered = entered.trim();
        if !entered.is_empty() && Path::new(entered).exists() {
            return Some(PathBuf::from(entered));
        }
        if attempt == PATH_ATTEMPTS {
            break;
        }
        prompt = format!(
            "'{entered}' does not exist. {PATH_PROMPT} ({} of {PATH_ATTEMPTS})",
            attempt + 1
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(product: Option<&str>, category: Option<&str>, service: Option<&str>) -> LogSourceSpec {
        LogSourceSpec::new(product, category, service)
    }

    fn find_row<'a>(rows: &'a [LocationRow], spec: &LogSourceSpec) -> Option<&'a LocationRow> {
        rows.iter().find(|r| r.logsource == *spec)
    }

    #[test]
    fn default_table_parses_with_the_expected_rows() {
        let rows = parse_log_locations(DEFAULT_LOG_LOCATIONS).unwrap();
        assert!(rows.len() >= 10, "{} rows", rows.len());
        let syslog = find_row(&rows, &spec(Some("linux"), None, Some("syslog")))
            .expect("row for {product: linux, service: syslog}");
        assert_eq!(syslog.patterns[0], "/var/log/syslog*");
        assert_eq!(syslog.patterns[1], "/var/log/messages*");
        let web = find_row(&rows, &spec(None, Some("webserver"), None))
            .expect("row for {category: webserver}");
        assert!(
            web.patterns
                .iter()
                .any(|p| p == "/var/log/apache2/access*.log*")
        );
        assert!(
            web.patterns
                .iter()
                .any(|p| p == "/var/log/nginx/access*.log*")
        );
        assert!(find_row(&rows, &spec(Some("linux"), None, None)).is_some());
        assert!(find_row(&rows, &spec(None, None, Some("apache"))).is_some());
        assert!(find_row(&rows, &spec(Some("php"), None, Some("fpm"))).is_some());
        for row in &rows {
            assert!(
                !row.patterns.is_empty(),
                "{} has no patterns",
                row.logsource
            );
            for p in &row.patterns {
                assert!(p.starts_with("/var/log/"), "{p} is not under /var/log");
                assert!(glob::Pattern::new(p).is_ok(), "{p} is not a valid glob");
            }
        }
    }

    #[test]
    fn table_values_are_normalized_like_rule_logsources() {
        let rows = parse_log_locations(
            "- logsource: {product: ' Linux ', service: SSHD}\n  paths: [\" /x/auth.log* \", \"\"]\n\
             - logsource: {category: WebServer}\n  paths: []\n\
             - logsource: {}\n  paths: [\"/x/*\"]\n",
        )
        .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].logsource, spec(Some("linux"), None, Some("sshd")));
        assert_eq!(rows[0].patterns, vec!["/x/auth.log*"]);
        assert_eq!(rows[1].logsource, spec(None, Some("webserver"), None));
        assert!(rows[1].patterns.is_empty());
        assert!(rows[2].logsource.is_empty());
    }

    #[test]
    fn comment_only_table_is_empty() {
        assert!(parse_log_locations("# nothing here\n").unwrap().is_empty());
        assert!(parse_log_locations("").unwrap().is_empty());
    }

    #[test]
    fn malformed_tables_are_errors() {
        for bad in [
            "- logsource: [\n",
            "logsource: {product: linux}\npaths: [a]\n",
            "- paths: [a]\n",
            "- logsource: {product: linux}\n",
            "- logsource: {product: linux}\n  paths: /var/log/syslog*\n",
            "- logsource: linux\n  paths: [a]\n",
            "just a string\n",
        ] {
            assert!(parse_log_locations(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn extra_tag_is_the_first_supported_tag_the_need_matches() {
        assert_eq!(
            extra_tag_for(&spec(None, None, Some("apache"))),
            Some(LogSourceTag::APACHE_ERROR)
        );
        assert_eq!(
            extra_tag_for(&spec(None, Some("webserver"), None)),
            Some(LogSourceTag::WEBSERVER)
        );
        assert_eq!(
            extra_tag_for(&spec(Some("linux"), None, None)),
            Some(LogSourceTag::LINUX_SYSLOG)
        );
        assert_eq!(
            extra_tag_for(&spec(Some("linux"), None, Some("sshd"))),
            Some(LogSourceTag::LINUX_SSHD)
        );
        assert_eq!(
            extra_tag_for(&spec(Some("php"), None, Some("fpm"))),
            Some(LogSourceTag::PHP_FPM)
        );
        assert_eq!(
            extra_tag_for(&spec(Some("nginx"), None, Some("error"))),
            Some(LogSourceTag::NGINX_ERROR_CANONICAL)
        );
        assert_eq!(
            extra_tag_for(&spec(Some("windows"), None, Some("security"))),
            None
        );
    }

    #[test]
    fn journal_is_wanted_only_without_syslog_files_and_with_linux_needs() {
        let linux = [spec(Some("linux"), None, Some("sshd"))];
        let web = [spec(None, Some("webserver"), None)];
        let syslog = ScanTarget::new(Path::new("/var/log/syslog"));
        let auth = ScanTarget::new(Path::new("/var/log/auth.log.1"));
        let access = ScanTarget::new(Path::new("/var/log/apache2/access.log"));
        let vsftpd = ScanTarget::new(Path::new("/var/log/vsftpd.log"));
        assert!(journal_wanted(&linux, []));
        assert!(journal_wanted(&linux, [&access]));
        assert!(
            journal_wanted(&linux, [&vsftpd]),
            "AppLog files are not syslog"
        );
        assert!(!journal_wanted(&linux, [&access, &syslog]));
        assert!(!journal_wanted(&linux, [&auth]));
        assert!(!journal_wanted(&web, []));
        assert!(!journal_wanted(&[], []));
    }

    #[test]
    fn the_journal_stands_in_for_syslog_and_sysmon_but_not_audit_logs() {
        assert!(is_linux(&LogSourceSpec::new(
            Some("linux"),
            None,
            Some("sshd")
        )));
        assert!(is_linux(&LogSourceSpec::new(
            Some("linux"),
            Some("process_creation"),
            None
        )));
        assert!(!is_linux(&LogSourceSpec::new(
            Some("linux"),
            None,
            Some("auditd")
        )));
        assert!(!is_linux(&LogSourceSpec::new(
            None,
            Some("webserver"),
            None
        )));
    }

    #[test]
    fn journalctl_is_not_found_with_an_empty_path() {
        assert_eq!(find_journalctl(""), None);
        assert_eq!(find_journalctl(OsString::new()), None);
    }

    #[test]
    fn spawning_a_missing_journalctl_fails() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-journalctl");
        assert!(spawn_journalctl(&missing, None).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn discover_is_linux_only() {
        let err = discover(&[], &[], &LiveOptions::default(), Path::new("rules")).unwrap_err();
        assert_eq!(err, "live analysis is only supported on Linux");
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;

        const SINCE: &str = "@1700000000";

        fn env(path_var: &Path) -> Environment {
            Environment {
                is_root: false,
                interactive: false,
                path_var: path_var.as_os_str().to_os_string(),
            }
        }

        fn no_wizard() -> LiveOptions {
            LiveOptions {
                no_wizard: true,
                no_color: true,
                since: None,
            }
        }

        fn row(
            product: Option<&str>,
            category: Option<&str>,
            service: Option<&str>,
            patterns: &[String],
        ) -> LocationRow {
            LocationRow {
                logsource: spec(product, category, service),
                patterns: patterns.to_vec(),
            }
        }

        /// The synthetic table of the brief, rooted at `root`.
        fn synthetic_rows(root: &Path) -> Vec<LocationRow> {
            let p = |s: &str| format!("{}/{s}", root.display());
            vec![
                row(
                    Some("linux"),
                    None,
                    Some("syslog"),
                    &[p("syslog*"), p("messages*")],
                ),
                row(
                    Some("linux"),
                    None,
                    Some("sshd"),
                    &[p("auth.log*"), p("secure*"), p("syslog*"), p("messages*")],
                ),
                row(Some("linux"), None, None, &[p("syslog*"), p("auth.log*")]),
                row(
                    None,
                    None,
                    Some("apache"),
                    &[p("apache2/error*.log*"), p("apache2/*error*.log*")],
                ),
                row(None, None, Some("nginx"), &[p("nginx/error*.log*")]),
                row(
                    None,
                    Some("webserver"),
                    None,
                    &[
                        p("apache2/access*.log*"),
                        p("apache2/*access*.log*"),
                        p("nginx/access*.log*"),
                    ],
                ),
                row(Some("php"), None, Some("fpm"), &[p("php*-fpm.log*")]),
            ]
        }

        fn populate(root: &Path) {
            std::fs::create_dir_all(root.join("apache2")).unwrap();
            std::fs::create_dir_all(root.join("nginx")).unwrap();
            for name in [
                "auth.log",
                "syslog",
                "apache2/error.log",
                "apache2/access.log",
                "nginx/error.log",
            ] {
                std::fs::write(root.join(name), format!("{name} line\n")).unwrap();
            }
        }

        fn brief_needs() -> Vec<LogSourceSpec> {
            vec![
                spec(Some("linux"), None, Some("sshd")),
                spec(Some("linux"), None, Some("syslog")),
                spec(None, None, Some("apache")),
                spec(None, Some("webserver"), None),
                spec(Some("php"), None, Some("fpm")),
            ]
        }

        fn paths_of(d: &LiveDiscovery) -> Vec<String> {
            d.targets
                .iter()
                .map(|t| t.path.display().to_string())
                .collect()
        }

        fn fake_journalctl(dir: &Path, body: &[u8]) -> PathBuf {
            let exe = dir.join("journalctl");
            std::fs::write(&exe, body).unwrap();
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
            exe
        }

        const ECHO_ARGS: &[u8] = b"#!/bin/sh\necho \"$@\"\n";

        #[test]
        fn synthetic_table_dedups_files_and_skips_needs_without_files() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            populate(root);
            let rows = synthetic_rows(root);
            let empty = tempfile::tempdir().unwrap();
            let d = discover_with(&brief_needs(), &rows, &no_wizard(), &env(empty.path()));
            let expected: Vec<String> = [
                "apache2/access.log",
                "apache2/error.log",
                "auth.log",
                "syslog",
            ]
            .iter()
            .map(|n| root.join(n).display().to_string())
            .collect();
            assert_eq!(
                paths_of(&d),
                expected,
                "one target per file, sorted by path"
            );
            for t in &d.targets {
                assert!(t.extra_tags.is_empty(), "rows never attach tags: {t:?}");
                assert_eq!(t.display_name, t.path.display().to_string());
                assert!(t.format.is_none());
            }
            assert_eq!(d.skipped, vec![spec(Some("php"), None, Some("fpm"))]);
            assert!(d.journal.is_none(), "a syslog file exists");
            assert_eq!(d.notes, vec![NOT_ROOT_NOTE.to_string()]);
        }

        #[test]
        fn public_discover_matches_the_internal_flow_without_a_wizard() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            populate(root);
            let rows = synthetic_rows(root);
            let d = discover(&brief_needs(), &rows, &no_wizard(), Path::new("rules")).unwrap();
            assert_eq!(d.targets.len(), 4);
            assert_eq!(d.skipped, vec![spec(Some("php"), None, Some("fpm"))]);
            assert!(d.journal.is_none());
            assert_eq!(
                d.notes.contains(&NOT_ROOT_NOTE.to_string()),
                !effective_uid_is_root()
            );
            assert!(!d.notes.contains(&NON_TTY_NOTE.to_string()));
        }

        #[test]
        fn needs_without_a_row_are_skipped() {
            let dir = tempfile::tempdir().unwrap();
            populate(dir.path());
            let rows = synthetic_rows(dir.path());
            let needs = [
                spec(Some("linux"), None, Some("syslog")),
                spec(Some("linux"), None, Some("cron")),
                spec(Some("php"), None, Some("error_log")),
            ];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert_eq!(d.targets.len(), 1);
            assert_eq!(d.skipped, vec![needs[1].clone(), needs[2].clone()]);
        }

        #[test]
        fn rows_with_the_same_triple_are_merged() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            std::fs::write(root.join("syslog"), "a\n").unwrap();
            std::fs::write(root.join("messages"), "b\n").unwrap();
            let p = |s: &str| format!("{}/{s}", root.display());
            let rows = [
                row(Some("linux"), None, Some("syslog"), &[p("syslog*")]),
                row(Some("linux"), None, Some("syslog"), &[p("messages*")]),
            ];
            let needs = [spec(Some("linux"), None, Some("syslog"))];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert_eq!(d.targets.len(), 2);
            assert!(d.skipped.is_empty());
        }

        #[test]
        fn directories_and_symlinked_duplicates_collapse_to_one_target() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            std::fs::write(root.join("syslog"), "a\n").unwrap();
            std::os::unix::fs::symlink(root.join("syslog"), root.join("syslog.link")).unwrap();
            std::fs::create_dir(root.join("syslog.d")).unwrap();
            let p = |s: &str| format!("{}/{s}", root.display());
            let rows = [row(Some("linux"), None, Some("syslog"), &[p("syslog*")])];
            let needs = [spec(Some("linux"), None, Some("syslog"))];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert_eq!(
                paths_of(&d),
                vec![root.join("syslog").display().to_string()]
            );
            assert!(d.skipped.is_empty());
        }

        #[test]
        fn rotated_and_gz_files_are_all_targets() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            for name in ["auth.log", "auth.log.1", "auth.log.2.gz", "secure-20261026"] {
                std::fs::write(root.join(name), "x\n").unwrap();
            }
            let p = |s: &str| format!("{}/{s}", root.display());
            let rows = [row(
                Some("linux"),
                None,
                Some("auth"),
                &[p("auth.log*"), p("secure*")],
            )];
            let needs = [spec(Some("linux"), None, Some("auth"))];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert_eq!(d.targets.len(), 4);
        }

        #[test]
        fn empty_need_is_satisfied_by_any_file() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            std::fs::write(root.join("syslog"), "a\n").unwrap();
            let p = |s: &str| format!("{}/{s}", root.display());
            let rows = [row(Some("linux"), None, Some("syslog"), &[p("syslog*")])];
            let needs = [
                spec(None, None, None),
                spec(Some("linux"), None, Some("syslog")),
            ];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert!(d.skipped.is_empty(), "{:?}", d.skipped);
            // ... but with no file at all it is skipped like any other need
            let d = discover_with(&needs[..1], &[], &no_wizard(), &env(Path::new("")));
            assert_eq!(d.skipped, vec![spec(None, None, None)]);
        }

        #[test]
        fn invalid_glob_pattern_is_a_note_not_a_panic() {
            let rows = [row(Some("php"), None, Some("fpm"), &["[".to_string()])];
            let needs = [spec(Some("php"), None, Some("fpm"))];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert!(d.targets.is_empty());
            assert!(
                d.notes
                    .iter()
                    .any(|n| n.starts_with("Invalid glob pattern '['")),
                "{:?}",
                d.notes
            );
            assert_eq!(d.skipped, needs.to_vec());
        }

        #[test]
        fn non_tty_without_no_wizard_skips_with_a_note() {
            let opts = LiveOptions {
                no_wizard: false,
                no_color: true,
                since: None,
            };
            let needs = [spec(None, Some("webserver"), None)];
            let d = discover_with(&needs, &[], &opts, &env(Path::new("")));
            assert_eq!(d.skipped, needs.to_vec());
            assert_eq!(
                d.notes,
                vec![NOT_ROOT_NOTE.to_string(), NON_TTY_NOTE.to_string()]
            );
        }

        #[test]
        fn root_gets_no_permission_warning() {
            let e = Environment {
                is_root: true,
                interactive: false,
                path_var: OsString::new(),
            };
            let d = discover_with(&[], &[], &no_wizard(), &e);
            assert!(d.notes.is_empty(), "{:?}", d.notes);
            assert!(d.targets.is_empty() && d.skipped.is_empty() && d.journal.is_none());
        }

        #[test]
        fn journalctl_lookup_finds_a_fake_executable_on_the_given_path() {
            let dir = tempfile::tempdir().unwrap();
            let exe = fake_journalctl(dir.path(), ECHO_ARGS);
            assert_eq!(find_journalctl(dir.path().as_os_str()), Some(exe.clone()));
            assert_eq!(find_journalctl(""), None);
            // several PATH entries: the first directory with an executable wins
            let other = tempfile::tempdir().unwrap();
            let joined = std::env::join_paths([other.path(), dir.path()]).unwrap();
            assert_eq!(find_journalctl(&joined), Some(exe.clone()));
            let joined = format!("{}:{}", dir.path().display(), other.path().display());
            assert_eq!(find_journalctl(joined), Some(exe.clone()));
            // a non-executable file of that name does not count
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(find_journalctl(dir.path().as_os_str()), None);
            // nor does a directory of that name
            let dir2 = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir2.path().join("journalctl")).unwrap();
            assert_eq!(find_journalctl(dir2.path().as_os_str()), None);
        }

        #[test]
        fn journal_is_spawned_with_the_expected_arguments_when_no_syslog_file_exists() {
            let bin = tempfile::tempdir().unwrap();
            fake_journalctl(bin.path(), ECHO_ARGS);
            let logs = tempfile::tempdir().unwrap();
            let p = |s: &str| format!("{}/{s}", logs.path().display());
            let rows = [
                row(Some("linux"), None, Some("sshd"), &[p("auth.log*")]),
                row(None, Some("webserver"), None, &[p("access*.log*")]),
            ];
            let needs = [
                spec(Some("linux"), None, Some("sshd")),
                spec(Some("linux"), None, Some("cron")),
                spec(None, Some("webserver"), None),
            ];
            let opts = LiveOptions {
                no_wizard: true,
                no_color: true,
                since: Some(SINCE.to_string()),
            };
            let mut d = discover_with(&needs, &rows, &opts, &env(bin.path()));
            assert!(d.targets.is_empty());
            let mut child = d.journal.take().expect("journalctl must be spawned");
            let mut out = String::new();
            child
                .stdout
                .take()
                .expect("stdout is piped")
                .read_to_string(&mut out)
                .unwrap();
            assert!(child.stderr.is_some(), "stderr is piped");
            assert!(child.wait().unwrap().success());
            assert_eq!(
                out.trim_end(),
                format!("--system --no-pager -o short-iso-precise --since {SINCE}")
            );
            // the journal satisfies the linux needs; only the web need is skipped
            assert_eq!(d.skipped, vec![spec(None, Some("webserver"), None)]);
            assert_eq!(
                d.notes,
                vec![NOT_ROOT_NOTE.to_string(), JOURNAL_NOTE.to_string()]
            );
        }

        #[test]
        fn journal_without_since_has_no_since_argument() {
            let bin = tempfile::tempdir().unwrap();
            let exe = fake_journalctl(bin.path(), ECHO_ARGS);
            let mut child = spawn_journalctl(&exe, None).unwrap();
            let mut out = String::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut out)
                .unwrap();
            assert!(child.wait().unwrap().success());
            assert_eq!(out.trim_end(), "--system --no-pager -o short-iso-precise");
            let mut child = spawn_journalctl(&exe, Some("  ")).unwrap();
            let mut out = String::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut out)
                .unwrap();
            assert!(child.wait().unwrap().success());
            assert_eq!(out.trim_end(), "--system --no-pager -o short-iso-precise");
        }

        #[test]
        fn journal_is_not_used_when_a_syslog_file_exists_or_no_linux_rule_needs_it() {
            let bin = tempfile::tempdir().unwrap();
            fake_journalctl(bin.path(), ECHO_ARGS);
            let logs = tempfile::tempdir().unwrap();
            std::fs::write(logs.path().join("syslog"), "a\n").unwrap();
            let p = |s: &str| format!("{}/{s}", logs.path().display());
            let rows = [row(Some("linux"), None, Some("syslog"), &[p("syslog*")])];
            // a syslog file exists
            let needs = [
                spec(Some("linux"), None, Some("syslog")),
                spec(Some("linux"), None, Some("cron")),
            ];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(bin.path()));
            assert!(d.journal.is_none());
            assert_eq!(d.skipped, vec![spec(Some("linux"), None, Some("cron"))]);
            // no rule needs product linux
            let needs = [spec(None, Some("webserver"), None)];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(bin.path()));
            assert!(d.journal.is_none());
            assert_eq!(d.skipped, needs.to_vec());
            // journalctl is not on PATH
            let needs = [spec(Some("linux"), None, Some("sshd"))];
            let d = discover_with(&needs, &[], &no_wizard(), &env(Path::new("")));
            assert!(d.journal.is_none());
            assert_eq!(d.skipped, needs.to_vec());
            assert!(!d.notes.contains(&JOURNAL_NOTE.to_string()));
        }

        #[test]
        fn journal_spawn_failure_is_a_note_and_the_needs_are_skipped() {
            let bin = tempfile::tempdir().unwrap();
            // executable, but execve fails with ENOENT on the missing interpreter (no shell
            // fallback, unlike ENOEXEC)
            fake_journalctl(bin.path(), b"#!/nonexistent/interpreter/for/iwatobi\n");
            let needs = [spec(Some("linux"), None, Some("sshd"))];
            let d = discover_with(&needs, &[], &no_wizard(), &env(bin.path()));
            assert!(d.journal.is_none());
            assert_eq!(d.skipped, needs.to_vec());
            assert!(
                d.notes
                    .iter()
                    .any(|n| n.starts_with("Could not run journalctl (")),
                "{:?}",
                d.notes
            );
        }

        #[test]
        fn unlistable_directory_yields_a_permission_note_and_no_skip() {
            if effective_uid_is_root() {
                // root can list anything; the scenario cannot be reproduced
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let locked = dir.path().join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::write(locked.join("cron"), "x\n").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let rows = [row(
                Some("linux"),
                None,
                Some("cron"),
                &[format!("{}/cron*", locked.display())],
            )];
            let needs = [spec(Some("linux"), None, Some("cron"))];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            // restore before asserting so the tempdir can be removed even on failure
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(d.targets.is_empty());
            assert!(d.skipped.is_empty(), "{:?}", d.skipped);
            let expected = format!("permission denied: {}", locked.display());
            assert!(
                d.notes.iter().any(|n| n.starts_with(&expected)),
                "{:?}",
                d.notes
            );
            assert!(d.journal.is_none());
        }

        #[test]
        fn unreadable_file_yields_a_permission_note_and_no_skip() {
            if effective_uid_is_root() {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let secret = root.join("auth.log");
            std::fs::write(&secret, "x\n").unwrap();
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
            std::fs::write(root.join("syslog"), "y\n").unwrap();
            let p = |s: &str| format!("{}/{s}", root.display());
            let rows = [
                row(Some("linux"), None, Some("auth"), &[p("auth.log*")]),
                row(
                    Some("linux"),
                    None,
                    Some("sshd"),
                    &[p("auth.log*"), p("syslog*")],
                ),
            ];
            let needs = [
                spec(Some("linux"), None, Some("auth")),
                spec(Some("linux"), None, Some("sshd")),
            ];
            let d = discover_with(&needs, &rows, &no_wizard(), &env(Path::new("")));
            assert_eq!(
                paths_of(&d),
                vec![root.join("syslog").display().to_string()]
            );
            assert!(d.skipped.is_empty(), "{:?}", d.skipped);
            assert_eq!(
                d.notes,
                vec![
                    NOT_ROOT_NOTE.to_string(),
                    format!("permission denied: {}", secret.display())
                ],
                "the note is pushed once although two rows hit the file"
            );
        }

        #[test]
        fn user_entered_paths_get_the_needed_tag_and_merge_into_existing_targets() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            std::fs::create_dir(root.join("sub")).unwrap();
            std::fs::write(root.join("a.log"), "a\n").unwrap();
            std::fs::write(root.join("sub/b.log"), "b\n").unwrap();
            let mut found = TargetSet::default();
            let sshd = spec(Some("linux"), None, Some("sshd"));
            assert_eq!(add_user_path(root, &sshd, &mut found), 2);
            let mut targets: Vec<&ScanTarget> = found.targets().collect();
            targets.sort_by(|a, b| a.path.cmp(&b.path));
            assert_eq!(targets[0].path, root.join("a.log"));
            assert_eq!(targets[1].path, root.join("sub/b.log"));
            for t in &targets {
                assert_eq!(t.extra_tags, vec![LogSourceTag::LINUX_SSHD]);
                assert_eq!(t.display_name, t.path.display().to_string());
            }
            // the same directory for another need adds the tag, not a duplicate target
            let linux = spec(Some("linux"), None, None);
            assert_eq!(add_user_path(root, &linux, &mut found), 0);
            for t in found.targets() {
                assert_eq!(
                    t.extra_tags,
                    vec![LogSourceTag::LINUX_SSHD, LogSourceTag::LINUX_SYSLOG]
                );
            }
            // a single file; a need with no supported tag adds the file without tags
            let one = root.join("c.log");
            std::fs::write(&one, "c\n").unwrap();
            let odd = spec(Some("windows"), None, Some("security"));
            assert_eq!(add_user_path(&one, &odd, &mut found), 1);
            let c = found.targets().find(|t| t.path == one).unwrap();
            assert!(c.extra_tags.is_empty());
            assert_eq!(found.into_targets().len(), 3);
        }
    }
}
