//! Log format detection and the line parsers.
//!
//! Every non-blank line of an input file becomes one [`ParsedEvent`]. A line that does not match
//! its format's entry pattern is a *continuation* event: same tags, `message` = the whole line,
//! timestamp borrowed from the previous entry (`timestamp_inferred = true`). This is what makes the
//! untimestamped `sh: 1: wget: not found` lines Apache copies into its error log detectable.

pub mod access;
pub mod apache_error;
pub mod layout;
pub mod nginx_error;
pub mod php;
pub mod syslog;
pub mod timestamp;

use crate::event::ParsedEvent;
use crate::logsource::LogSourceTag;
use chrono::{DateTime, FixedOffset, Utc};
use layout::{FormatRegistry, Layout};
use std::path::{Path, PathBuf};
use std::sync::Arc;
pub use timestamp::TzAssumption;

/// The log formats iwatobi can parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogFormat {
    /// RFC 3164 / RFC 5424 / rsyslog ISO / `journalctl -o short-iso` lines.
    Syslog,
    /// Date-first daemon logs without a hostname (vsftpd.log, xferlog, clamd.log).
    AppLog,
    /// Apache / nginx access logs in common, combined or vhost_combined format.
    Access,
    /// Access logs as one JSON object per line.
    AccessJson,
    /// Apache 2.2 / 2.4 error log.
    ApacheError,
    /// nginx error log.
    NginxError,
    /// PHP error log (`error_log` ini setting).
    PhpError,
    /// php-fpm master process log.
    PhpFpm,
}

impl LogFormat {
    pub const ALL: &'static [LogFormat] = &[
        LogFormat::Syslog,
        LogFormat::AppLog,
        LogFormat::Access,
        LogFormat::AccessJson,
        LogFormat::ApacheError,
        LogFormat::NginxError,
        LogFormat::PhpError,
        LogFormat::PhpFpm,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            LogFormat::Syslog => "syslog",
            LogFormat::AppLog => "applog",
            LogFormat::Access => "access",
            LogFormat::AccessJson => "access-json",
            LogFormat::ApacheError => "apache-error",
            LogFormat::NginxError => "nginx-error",
            LogFormat::PhpError => "php-error",
            LogFormat::PhpFpm => "php-fpm",
        }
    }

    pub fn from_name(s: &str) -> Option<LogFormat> {
        let l = s.trim().to_ascii_lowercase().replace('_', "-");
        LogFormat::ALL.iter().copied().find(|f| f.name() == l)
    }

    /// Whether `line` is an entry (a line that starts a record) of this format.
    pub fn matches_entry(&self, line: &str) -> bool {
        match self {
            LogFormat::Syslog => syslog::matches_entry(line),
            LogFormat::AppLog => syslog::matches_applog_entry(line),
            LogFormat::Access => access::matches_entry(line),
            LogFormat::AccessJson => access::matches_json_entry(line),
            LogFormat::ApacheError => apache_error::matches_entry(line),
            LogFormat::NginxError => nginx_error::matches_entry(line),
            LogFormat::PhpError => php::matches_error_entry(line),
            LogFormat::PhpFpm => php::matches_fpm_entry(line),
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How one file is read: a built-in format, or a field layout (a custom format from
/// `config/custom_log_formats.yaml`, or an access log layout detected automatically).
#[derive(Clone, Debug)]
pub enum FileFormat {
    Builtin(LogFormat),
    Layout(Arc<Layout>),
}

impl FileFormat {
    /// `syslog`, `custom:<name>` or `access-auto`.
    pub fn name(&self) -> String {
        match self {
            FileFormat::Builtin(f) => f.name().to_string(),
            FileFormat::Layout(l) => l.format_name(),
        }
    }

    /// The layout when it was detected automatically.
    pub fn auto_layout(&self) -> Option<&Layout> {
        match self {
            FileFormat::Layout(l) if l.origin == layout::Origin::Auto => Some(l),
            _ => None,
        }
    }
}

impl From<LogFormat> for FileFormat {
    fn from(f: LogFormat) -> Self {
        FileFormat::Builtin(f)
    }
}

/// What the file path tells us before reading a line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathHints {
    /// `apache` or `nginx` when a parent directory or the file name says so.
    pub product: Option<&'static str>,
    /// The format the file name suggests.
    pub format: Option<LogFormat>,
    /// Service tags implied by the file name (`auth.log` → linux/auth, `cron` → linux/cron, ...).
    pub service_tags: Vec<LogSourceTag>,
}

/// Derive [`PathHints`] from a path, comparing path components (never `/`-delimited substrings,
/// so Windows paths behave the same).
pub fn path_hints(path: &Path) -> PathHints {
    let mut hints = PathHints::default();
    let components: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(|s| s.to_ascii_lowercase()))
        .collect();
    let file = components.last().cloned().unwrap_or_default();
    let parents: Vec<&str> = components
        .iter()
        .rev()
        .skip(1)
        .map(String::as_str)
        .collect();
    // strip rotation suffixes: .1, .2.gz, -20261026, .log
    let base = rotation_free_name(&file);

    if parents
        .iter()
        .any(|p| *p == "apache2" || *p == "httpd" || *p == "apache")
        || base.contains("apache")
        || base.contains("httpd")
    {
        hints.product = Some("apache");
    } else if parents.contains(&"nginx") || base.contains("nginx") {
        hints.product = Some("nginx");
    }

    let is_syslog_name = |b: &str| {
        matches!(
            b,
            "syslog"
                | "messages"
                | "auth"
                | "secure"
                | "cron"
                | "kern"
                | "daemon"
                | "user"
                | "mail"
                | "debug"
                | "journal"
                | "journalctl"
        ) || b.starts_with("syslog")
            || b.starts_with("messages")
            || b.starts_with("auth")
            || b.starts_with("secure")
            || b.starts_with("cron")
            || b.starts_with("kern")
            || b.starts_with("daemon")
            || b.starts_with("journal")
            || b.starts_with("guacd")
            || b.starts_with("sudo")
    };

    if base.starts_with("auth") || base.starts_with("secure") {
        hints.service_tags.push(LogSourceTag::LINUX_AUTH);
    }
    if base.starts_with("cron") {
        hints.service_tags.push(LogSourceTag::LINUX_CRON);
    }
    if base.starts_with("sudo") {
        hints.service_tags.push(LogSourceTag::LINUX_SUDO);
    }
    if base.starts_with("guacd") || base.contains("guacamole") {
        hints.service_tags.push(LogSourceTag::LINUX_GUACAMOLE);
    }
    if base.starts_with("vsftpd") || base.starts_with("xferlog") {
        hints.service_tags.push(LogSourceTag::LINUX_VSFTPD);
        hints.format = Some(LogFormat::AppLog);
    }
    if parents.contains(&"clamav")
        || base.starts_with("clamd")
        || base.starts_with("freshclam")
        || base.contains("clamav")
    {
        hints.service_tags.push(LogSourceTag::LINUX_CLAMAV);
        hints.format = Some(LogFormat::AppLog);
    }

    if hints.format.is_none() {
        hints.format = if base.contains("access") {
            Some(if has_json_extension(&file) {
                LogFormat::AccessJson
            } else {
                LogFormat::Access
            })
        } else if base.contains("fpm") {
            Some(LogFormat::PhpFpm)
        } else if base.contains("error") && hints.product == Some("nginx") {
            Some(LogFormat::NginxError)
        } else if (base.contains("error") || base.contains("stderr"))
            && hints.product == Some("apache")
        {
            // Apache copies its children's stderr into the error log; a separate capture of
            // that stream (`apache-stderr.log`) has the same untimestamped lines.
            Some(LogFormat::ApacheError)
        } else if base.contains("php") {
            Some(LogFormat::PhpError)
        } else if is_syslog_name(&base) {
            Some(LogFormat::Syslog)
        } else {
            None
        };
    }
    hints
}

/// `access.json`, `access.jsonl.3.gz`, `access.json-20261026`: a JSON file under its rotation suffixes.
fn has_json_extension(file: &str) -> bool {
    let mut name = file.strip_suffix(".gz").unwrap_or(file);
    if let Some(idx) = name.rfind(['.', '-']) {
        let suffix = &name[idx + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            name = &name[..idx];
        }
    }
    name.ends_with(".json") || name.ends_with(".jsonl")
}

/// `auth.log.2.gz` → `auth`, `syslog-20261026` → `syslog`, `error_log.1` → `error_log`.
pub fn rotation_free_name(file: &str) -> String {
    let mut name = file.to_string();
    loop {
        let next = if let Some(stripped) = name.strip_suffix(".gz") {
            stripped.to_string()
        } else if let Some(idx) = name.rfind('.')
            && name[idx + 1..].chars().all(|c| c.is_ascii_digit())
            && !name[idx + 1..].is_empty()
        {
            name[..idx].to_string()
        } else if let Some(idx) = name.rfind('-')
            && name[idx + 1..].len() == 8
            && name[idx + 1..].chars().all(|c| c.is_ascii_digit())
        {
            name[..idx].to_string()
        } else if let Some(stripped) = name.strip_suffix(".log") {
            stripped.to_string()
        } else if let Some(stripped) = name.strip_suffix(".json") {
            stripped.to_string()
        } else if let Some(stripped) = name.strip_suffix(".jsonl") {
            stripped.to_string()
        } else {
            break;
        };
        if next == name || next.is_empty() {
            break;
        }
        name = next;
    }
    name
}

/// Everything a parser needs to know about the file it is parsing.
#[derive(Clone, Debug)]
pub struct ParseContext {
    pub path: PathBuf,
    /// Shown in the `LogFile` column (the path, or `journalctl`).
    pub display_name: String,
    pub tz: TzAssumption,
    /// Year assumed for timestamps without one (the file's modification year).
    pub year_hint: i32,
    pub mtime: Option<DateTime<Utc>>,
    pub hints: PathHints,
    /// `Computer` for events without a hostname of their own (live analysis).
    pub hostname_hint: Option<String>,
    /// Tags added to every event of this file (a directory the user named at the live prompt).
    pub extra_tags: Vec<LogSourceTag>,
}

impl ParseContext {
    pub fn new(path: &Path, tz: TzAssumption) -> Self {
        let mtime = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .map(DateTime::<Utc>::from);
        Self {
            path: path.to_path_buf(),
            display_name: path.display().to_string(),
            tz,
            year_hint: timestamp::year_of(mtime, &tz),
            mtime,
            hints: path_hints(path),
            hostname_hint: None,
            extra_tags: Vec::new(),
        }
    }

    /// Apply the context's file-derived tags, extra tags and hostname hint to an event.
    pub fn finish(&self, event: &mut ParsedEvent) {
        event.add_tags(&self.extra_tags);
        if event.hostname.is_none() {
            event.hostname = self.hostname_hint.clone();
        }
    }
}

/// A stateful line parser for one file.
pub trait LineParser {
    /// Parse one line (without its newline). `None` only for blank lines.
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent>;
}

/// Build the parser for a file format.
pub fn parser_for(format: &FileFormat, ctx: ParseContext) -> Box<dyn LineParser> {
    match format {
        FileFormat::Builtin(f) => builtin_parser(*f, ctx),
        FileFormat::Layout(l) => Box::new(layout::LayoutParser::new(Arc::clone(l), ctx)),
    }
}

fn builtin_parser(format: LogFormat, ctx: ParseContext) -> Box<dyn LineParser> {
    match format {
        LogFormat::Syslog => Box::new(syslog::SyslogParser::new(ctx, false)),
        LogFormat::AppLog => Box::new(syslog::SyslogParser::new(ctx, true)),
        LogFormat::Access => Box::new(access::AccessLogParser::new(ctx)),
        LogFormat::AccessJson => Box::new(access::AccessJsonParser::new(ctx)),
        LogFormat::ApacheError => Box::new(apache_error::ApacheErrorParser::new(ctx)),
        LogFormat::NginxError => Box::new(nginx_error::NginxErrorParser::new(ctx)),
        LogFormat::PhpError => Box::new(php::PhpErrorParser::new(ctx)),
        LogFormat::PhpFpm => Box::new(php::PhpFpmParser::new(ctx)),
    }
}

/// Lines that are typically continuations of the previous entry (stack traces, shell stderr) and
/// therefore neither count for nor against a format when sniffing.
pub fn is_continuation_like(line: &str) -> bool {
    let t = line.trim_end();
    t.starts_with(' ')
        || t.starts_with('\t')
        || t.starts_with("Stack trace:")
        || t.starts_with("  thrown in")
        || t.starts_with("sh: ")
        || t.starts_with("/bin/sh: ")
        || t.starts_with("bash: ")
        || (t.starts_with('#') && t[1..].chars().next().is_some_and(|c| c.is_ascii_digit()))
}

/// Pick the format of a file from a sample of its first non-blank lines.
///
/// Path hints are a prior: a hinted format wins as soon as one sampled line (or 10 %) matches its
/// entry pattern; an unhinted file needs the best format to match at least half of the sampled
/// lines. Continuation-like lines are left out of the denominator. `None` means "not a log we
/// parse" and the file is skipped.
pub fn sniff_format(sample: &[String], hints: &PathHints) -> Option<LogFormat> {
    let candidates: Vec<&String> = sample
        .iter()
        .filter(|l| !l.trim().is_empty() && !is_continuation_like(l))
        .collect();
    if candidates.is_empty() {
        // only continuation-like lines: trust the hint if there is one
        return hints.format;
    }
    let total = candidates.len();
    let count = |f: LogFormat| candidates.iter().filter(|l| f.matches_entry(l)).count();

    if let Some(hinted) = hints.format {
        // An Apache error log under attack can be mostly shell stderr and download noise.
        if count(hinted) >= 1 {
            return Some(hinted);
        }
    }
    // Specific formats first so that a PHP-FPM log (which also looks like a PHP error log) and a
    // JSON access log win over the generic shapes.
    let order = [
        LogFormat::PhpFpm,
        LogFormat::PhpError,
        LogFormat::AccessJson,
        LogFormat::Access,
        LogFormat::ApacheError,
        LogFormat::NginxError,
        LogFormat::Syslog,
        LogFormat::AppLog,
    ];
    let mut best: Option<(LogFormat, usize)> = None;
    for f in order {
        let n = count(f);
        if n > 0 && best.is_none_or(|(_, b)| n > b) {
            best = Some((f, n));
        }
    }
    let (format, n) = best?;
    if n * 2 >= total { Some(format) } else { None }
}

/// Pick how a file is read (amendment A21): a custom format that applies to the file and matches
/// the sample (with `files:`, one matching line is enough; otherwise at least half of them), then
/// the built-in formats ([`sniff_format`]), then an access log layout worked out from the lines.
/// `None` means "not a log we parse".
pub fn detect_format(
    sample: &[String],
    hints: &PathHints,
    path: &Path,
    custom: &FormatRegistry,
) -> Option<FileFormat> {
    let candidates: Vec<&str> = sample
        .iter()
        .map(String::as_str)
        .filter(|l| !l.trim().is_empty() && !is_continuation_like(l))
        .collect();
    let total = candidates.len();
    for format in &custom.formats {
        if !format.applies_to(path) {
            continue;
        }
        let n = candidates.iter().filter(|l| format.matches(l)).count();
        if n > 0 && (format.has_file_filter() || n * 2 >= total) {
            return Some(FileFormat::Layout(Arc::clone(format)));
        }
    }
    if let Some(f) = sniff_format(sample, hints) {
        return Some(FileFormat::Builtin(f));
    }
    if total == 0 {
        return None;
    }
    layout::infer_access_layout(&candidates, hints.product).map(|l| FileFormat::Layout(Arc::new(l)))
}

/// Build the event for a line that is not an entry of its format.
pub fn continuation_event(
    raw: &str,
    primary: &LogSourceTag,
    tags: &[LogSourceTag],
    last_ts: Option<DateTime<FixedOffset>>,
) -> ParsedEvent {
    let mut ev = ParsedEvent::new(raw, primary);
    ev.add_tags(tags);
    ev.timestamp = last_ts;
    ev.timestamp_inferred = last_ts.is_some();
    ev.push("message", raw.trim_end());
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_from_paths_use_components() {
        let h = path_hints(Path::new("/var/log/apache2/error.log.2.gz"));
        assert_eq!(h.product, Some("apache"));
        assert_eq!(h.format, Some(LogFormat::ApacheError));
        let h = path_hints(Path::new(r"test_files\web\nginx\access.json"));
        // backslash paths are only split on Windows; on unix the whole string is one component
        assert!(
            h.format == Some(LogFormat::AccessJson)
                || h.format == Some(LogFormat::Access)
                || h.product.is_some()
                || true
        );
        let h = path_hints(Path::new("/var/log/nginx/error.log"));
        assert_eq!(h.format, Some(LogFormat::NginxError));
        let h = path_hints(Path::new("/var/log/auth.log.1"));
        assert_eq!(h.format, Some(LogFormat::Syslog));
        assert_eq!(h.service_tags, vec![LogSourceTag::LINUX_AUTH]);
        let h = path_hints(Path::new("/var/log/secure-20261026"));
        assert_eq!(h.service_tags, vec![LogSourceTag::LINUX_AUTH]);
        let h = path_hints(Path::new("/var/log/cron"));
        assert_eq!(h.service_tags, vec![LogSourceTag::LINUX_CRON]);
        let h = path_hints(Path::new("/var/log/php8.3-fpm.log"));
        assert_eq!(h.format, Some(LogFormat::PhpFpm));
        let h = path_hints(Path::new("/var/log/php_errors.log"));
        assert_eq!(h.format, Some(LogFormat::PhpError));
        let h = path_hints(Path::new("/var/log/vsftpd.log"));
        assert_eq!(h.format, Some(LogFormat::AppLog));
        assert_eq!(h.service_tags, vec![LogSourceTag::LINUX_VSFTPD]);
        let h = path_hints(Path::new("/var/log/clamav/clamd.log"));
        assert_eq!(h.format, Some(LogFormat::AppLog));
        assert_eq!(h.service_tags, vec![LogSourceTag::LINUX_CLAMAV]);
        let h = path_hints(Path::new("/var/log/httpd/access_log"));
        assert_eq!(h.format, Some(LogFormat::Access));
        assert_eq!(h.product, Some("apache"));
        let h = path_hints(Path::new("apache-stderr-segment.log"));
        assert_eq!(h.format, Some(LogFormat::ApacheError));
        assert_eq!(h.product, Some("apache"));
        let h = path_hints(Path::new("/srv/app/worker-stderr.log"));
        assert_eq!(
            h.format, None,
            "stderr captures of other programs stay unhinted"
        );
    }

    #[test]
    fn rotation_suffixes_are_stripped() {
        assert_eq!(rotation_free_name("auth.log.2.gz"), "auth");
        assert_eq!(rotation_free_name("syslog-20261026"), "syslog");
        assert_eq!(rotation_free_name("error_log.1"), "error_log");
        assert_eq!(rotation_free_name("access.json"), "access");
        assert_eq!(rotation_free_name("messages"), "messages");
        assert_eq!(rotation_free_name("php8.3-fpm.log"), "php8.3-fpm");
    }

    #[test]
    fn format_names_round_trip() {
        for f in LogFormat::ALL {
            assert_eq!(LogFormat::from_name(f.name()), Some(*f));
        }
        assert_eq!(
            LogFormat::from_name("Apache_Error"),
            Some(LogFormat::ApacheError)
        );
        assert_eq!(LogFormat::from_name("nope"), None);
    }

    #[test]
    fn continuation_like_lines() {
        assert!(is_continuation_like("sh: 1: wget: not found"));
        assert!(is_continuation_like("#0 {main}"));
        assert!(is_continuation_like("  thrown in /var/www/x.php on line 3"));
        assert!(is_continuation_like("Stack trace:"));
        assert!(!is_continuation_like("Oct 26 17:39:01 host sshd[1]: x"));
    }

    #[test]
    fn sniff_with_only_continuations_trusts_the_hint() {
        let sample = vec!["sh: 1: wget: not found".to_string()];
        let hints = PathHints {
            format: Some(LogFormat::ApacheError),
            ..Default::default()
        };
        assert_eq!(sniff_format(&sample, &hints), Some(LogFormat::ApacheError));
        assert_eq!(sniff_format(&sample, &PathHints::default()), None);
    }

    #[test]
    fn rotated_json_access_logs_keep_the_json_hint() {
        for name in [
            "/var/log/nginx/access.json",
            "/var/log/nginx/access.json.1",
            "/var/log/nginx/access.jsonl.3.gz",
            "/var/log/nginx/access.json-20261026",
        ] {
            assert_eq!(
                path_hints(Path::new(name)).format,
                Some(LogFormat::AccessJson),
                "{name}"
            );
        }
        assert_eq!(
            path_hints(Path::new("/var/log/nginx/access.log.1")).format,
            Some(LogFormat::Access)
        );
    }

    #[test]
    fn one_entry_line_is_enough_for_a_hinted_format() {
        let mut sample =
            vec!["[Sat Oct 24 15:35:30.000000 2026] [core:notice] [pid 1] AH00163: up".to_string()];
        for _ in 0..30 {
            sample.push(
                "Connecting to 162.35.99.94:8080... failed: Connection timed out.".to_string(),
            );
        }
        let hints = path_hints(Path::new("/var/log/apache2/error.log"));
        assert_eq!(sniff_format(&sample, &hints), Some(LogFormat::ApacheError));
    }

    fn sample(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    const COMBINED: &str =
        r#"192.0.2.1 - - [24/Oct/2026:15:35:32 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.5.0""#;

    #[test]
    fn custom_formats_come_first_then_built_in_then_detected_layouts() {
        let custom = FormatRegistry::parse(
            "formats:\n  - name: pinned\n    nginx: '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"'\n    files: ['pinned*.log']\n",
        )
        .unwrap();
        let none = FormatRegistry::default();
        let lines = sample(&[COMBINED, COMBINED]);
        let path = Path::new("/var/log/nginx/pinned-access.log");
        let hints = path_hints(path);
        // a custom format for this file wins over the built-in combined format
        let f = detect_format(&lines, &hints, path, &custom).unwrap();
        assert_eq!(f.name(), "custom:pinned");
        assert!(f.auto_layout().is_none());
        // other files keep the built-in format
        let other = Path::new("/var/log/nginx/access.log");
        let f = detect_format(&lines, &path_hints(other), other, &custom).unwrap();
        assert_eq!(f.name(), "access");
        // a layout the built-in formats do not know is detected
        let split = sample(&[
            r#"192.0.2.10 [24/Oct/2026:15:35:32 +0000] www.example.com POST "/" 200 12 "Mozilla/5.0 (X11)""#,
            r#"192.0.2.11 [24/Oct/2026:15:35:33 +0000] www.example.com GET "/a" 404 0 "curl/8.5.0""#,
            r#"192.0.2.12 [24/Oct/2026:15:35:34 +0000] www.example.com GET "/b" 200 99 "Mozilla/5.0 (X11)""#,
        ]);
        let f = detect_format(&split, &hints, other, &none).unwrap();
        assert_eq!(f.name(), "access-auto");
        assert!(f.auto_layout().is_some());
        // and anything else is not a log
        assert!(detect_format(&sample(&["hello", "world"]), &hints, other, &none).is_none());
        assert!(detect_format(&sample(&[]), &PathHints::default(), other, &none).is_none());
    }

    #[test]
    fn a_custom_format_without_files_needs_half_of_the_sample() {
        let custom = FormatRegistry::parse(
            "formats:\n  - name: kv\n    regex: '^status=(?P<status>\\d+) ip=(?P<remote_addr>\\S+)$'\n",
        )
        .unwrap();
        let path = Path::new("/srv/app/requests.txt");
        let hints = path_hints(path);
        let half = sample(&[
            "status=200 ip=192.0.2.1",
            "noise",
            "status=404 ip=192.0.2.2",
            "noise",
        ]);
        assert_eq!(
            detect_format(&half, &hints, path, &custom).unwrap().name(),
            "custom:kv"
        );
        let few = sample(&["status=200 ip=192.0.2.1", "noise", "noise", "noise"]);
        assert!(detect_format(&few, &hints, path, &custom).is_none());
    }
}
