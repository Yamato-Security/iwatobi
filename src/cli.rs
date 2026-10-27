//! Command line definition (clap derive). Option letters and help headings follow Hayabusa and
//! Suzaku so a user of the sibling tools finds the same flags in the same places.

use crate::parsers::{LogFormat, TzAssumption};
use chrono::DateTime;
use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub const RELEASE_NAME: &str = "Vulnpocalypse Release";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (Vulnpocalypse Release)");
const AUTHOR: &str =
    "Yamato Security (https://github.com/Yamato-Security/iwatobi - @SecurityYamato)";

/// Validate `--timeline-start` / `--timeline-end` up front.
fn parse_time_bound(s: &str) -> Result<String, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|_| s.to_string())
        .map_err(|_| {
            format!("'{s}' is not a valid RFC 3339 date-time (e.g. \"2026-10-24T15:35:00Z\")")
        })
}

/// Validate `--time-offset` (`1y`, `3M`, `30d`, `24h`, `30m`).
pub fn parse_time_offset(s: &str) -> Result<String, String> {
    offset_to_seconds(s)
        .map(|_| s.to_string())
        .ok_or_else(|| format!("'{s}' is not a valid time offset (e.g. 1y, 3M, 30d, 24h, 30m)"))
}

/// Seconds for a time offset such as `1y`, `3M`, `30d`, `24h`, `30m`, `90s`.
pub fn offset_to_seconds(s: &str) -> Option<i64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = s.split_at(split);
    let n: i64 = num.parse().ok()?;
    let mult: i64 = match unit {
        "y" => 365 * 24 * 3600,
        "M" => 30 * 24 * 3600,
        "w" => 7 * 24 * 3600,
        "d" => 24 * 3600,
        "h" => 3600,
        "m" => 60,
        "s" => 1,
        _ => return None,
    };
    // Reject offsets that overflow or reach before the representable time range, instead of
    // wrapping around or panicking when the start time is computed.
    let secs = n.checked_mul(mult)?;
    chrono::TimeDelta::try_seconds(secs)
        .and_then(|d| chrono::Utc::now().checked_sub_signed(d))
        .map(|_| secs)
}

fn parse_tz(s: &str) -> Result<TzAssumption, String> {
    s.parse::<TzAssumption>()
}

/// The text of the "not a log format" error: the built-in names and the custom ones.
pub fn log_format_error(name: &str, custom: &[String]) -> String {
    let mut valid: Vec<String> = LogFormat::ALL
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    valid.extend(custom.iter().cloned());
    format!(
        "'{name}' is not a log format. Valid values: {}",
        valid.join(", ")
    )
}

fn parse_level(s: &str) -> Result<String, String> {
    const VALID: &[&str] = &[
        "informational",
        "info",
        "low",
        "medium",
        "med",
        "high",
        "critical",
        "crit",
    ];
    let l = s.to_ascii_lowercase();
    if VALID.contains(&l.as_str()) {
        Ok(l)
    } else {
        Err(format!(
            "'{s}' is not a level. Valid levels: informational, low, medium, high, critical"
        ))
    }
}

/// Output file formats selectable with `-t, --output-type`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    Csv,
    Json,
    Jsonl,
}

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Csv => "csv",
            OutputFormat::Json => "json",
            OutputFormat::Jsonl => "jsonl",
        }
    }
}

#[derive(Parser)]
#[command(name = "iwatobi")]
#[command(version = FULL_VERSION)]
#[command(author = AUTHOR)]
#[command(about = "Linux Log Threat Detection and Fast Forensics")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Args, Clone, Debug, Default)]
pub struct CommonOptions {
    /// Show the help menu
    #[clap(help_heading = Some("General Options"), short = 'h', long = "help", action = ArgAction::Help, required = false, display_order = 10)]
    pub help: Option<bool>,

    /// Disable color output
    #[arg(help_heading = Some("Display Settings"), short = 'K', long = "no-color", global = true, display_order = 400)]
    pub no_color: bool,

    /// Quiet mode: do not display the launch banner
    #[arg(help_heading = Some("Display Settings"), short, long, global = true, display_order = 402)]
    pub quiet: bool,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath", "live_analysis"]).required(true).multiple(false)))]
pub struct InputOption {
    /// Directory of log files (scanned recursively; rotated and .gz files included)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one log file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Analyze the local log files that the loaded rules need (/var/log, journalctl)
    #[arg(help_heading = Some("Input"), short = 'l', long = "live-analysis", display_order = 102)]
    pub live_analysis: bool,

    /// Force the log format of every input file instead of detecting it: syslog, applog, access,
    /// access-json, apache-error, nginx-error, php-error, php-fpm, or the name of a custom format
    #[arg(help_heading = Some("Input"), long = "log-format", value_name = "FORMAT", display_order = 103)]
    pub log_format: Option<String>,

    /// Custom log format definitions (default: config/custom_log_formats.yaml)
    #[arg(help_heading = Some("Input"), long = "custom-formats", value_name = "FILE", display_order = 104)]
    pub custom_formats: Option<PathBuf>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct FilterOption {
    /// Minimum level for rules to load (default: informational)
    #[arg(help_heading = Some("Filtering"), short = 'm', long = "min-level", default_value = "informational", hide_default_value = true, value_name = "LEVEL", value_parser = parse_level, display_order = 200)]
    pub min_level: String,

    /// Enable rules with a status of deprecated
    #[arg(help_heading = Some("Filtering"), short = 'D', long = "enable-deprecated-rules", display_order = 201)]
    pub enable_deprecated_rules: bool,

    /// Enable rules with a status of unsupported
    #[arg(help_heading = Some("Filtering"), short = 'u', long = "enable-unsupported-rules", display_order = 202)]
    pub enable_unsupported_rules: bool,

    /// Do not load rules according to status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "exclude-status", value_name = "STATUS...", value_delimiter = ',', conflicts_with = "include_status", display_order = 203)]
    pub exclude_status: Vec<String>,

    /// Only load rules with specific status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "include-status", value_name = "STATUS...", value_delimiter = ',', display_order = 204)]
    pub include_status: Vec<String>,

    /// Only load rules with specific tags (ex: attack.execution,attack.discovery)
    #[arg(help_heading = Some("Filtering"), long = "include-tag", value_name = "TAG...", value_delimiter = ',', conflicts_with = "exclude_tag", display_order = 205)]
    pub include_tag: Vec<String>,

    /// Do not load rules with specific tags (ex: attack.execution,attack.discovery)
    #[arg(help_heading = Some("Filtering"), long = "exclude-tag", value_name = "TAG...", value_delimiter = ',', display_order = 206)]
    pub exclude_tag: Vec<String>,

    /// Start time of the events to load (ex: "2026-10-24T15:35:00Z")
    #[arg(help_heading = Some("Filtering"), long = "timeline-start", value_name = "DATE", value_parser = parse_time_bound, display_order = 210)]
    pub timeline_start: Option<String>,

    /// End time of the events to load (ex: "2026-10-24T16:00:00Z")
    #[arg(help_heading = Some("Filtering"), long = "timeline-end", value_name = "DATE", value_parser = parse_time_bound, display_order = 211)]
    pub timeline_end: Option<String>,

    /// Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
    #[arg(help_heading = Some("Filtering"), long = "time-offset", value_name = "OFFSET", value_parser = parse_time_offset, conflicts_with = "timeline_start", display_order = 212)]
    pub time_offset: Option<String>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct OutputOption {
    /// Save the results to a file. The extension is set to the output type (ex: -o timeline -t csv,jsonl writes timeline.csv and timeline.jsonl)
    #[arg(help_heading = Some("Output"), short, long, value_name = "FILE", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output format(s) (only used with -o): csv (default), json, jsonl. Comma-separate to write several, e.g. -t csv,jsonl
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_enum, value_delimiter = ',', default_value = "csv", value_name = "FORMAT,...", display_order = 301)]
    pub output_types: Vec<OutputFormat>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long = "clobber", requires = "output", display_order = 302)]
    pub clobber: bool,

    /// Output profile (default: standard on the terminal, verbose for files). See list-profiles
    #[arg(help_heading = Some("Output"), short = 'p', long = "profile", value_name = "PROFILE", display_order = 303)]
    pub profile: Option<String>,

    /// Sort events before output (warning: this uses much more memory!)
    #[arg(help_heading = Some("Output"), short = 's', long = "sort", display_order = 304)]
    pub sort: bool,

    /// Do not display the results summary
    #[arg(help_heading = Some("Display Settings"), short = 'N', long = "no-summary", display_order = 401)]
    pub no_summary: bool,

    /// Output time in UTC format (default: local time)
    #[arg(help_heading = Some("Time Format"), short = 'U', long = "utc", display_order = 350)]
    pub utc: bool,
}

#[derive(Args, Clone, Debug, Default)]
pub struct GeneralOption {
    /// Specify a custom rule directory or file (default: ./rules)
    #[arg(help_heading = Some("General Options"), short = 'r', long, default_value = "./rules", hide_default_value = true, value_name = "DIR/FILE", display_order = 11)]
    pub rules: PathBuf,

    /// Timezone of log timestamps that have no timezone information (ex: UTC, Asia/Tokyo, +09:00) (default: local)
    #[arg(help_heading = Some("General Options"), short = 'z', long = "timezone", value_name = "TZ", value_parser = parse_tz, allow_hyphen_values = true, display_order = 12)]
    pub timezone: Option<TzAssumption>,

    /// Quiet errors mode: do not save error logs
    #[arg(help_heading = Some("General Options"), short = 'Q', long = "quiet-errors", display_order = 13)]
    pub quiet_errors: bool,

    /// Do not ask questions (live analysis skips rules whose logs are not found)
    #[arg(help_heading = Some("General Options"), short = 'w', long = "no-wizard", display_order = 14)]
    pub no_wizard: bool,

    /// Number of threads (default: optimal number for performance)
    #[arg(help_heading = Some("General Options"), long = "threads", value_name = "NUMBER", display_order = 15)]
    pub threads: Option<usize>,

    /// Output verbose information (detected log formats, skipped files)
    #[arg(help_heading = Some("Display Settings"), short = 'v', long, display_order = 403)]
    pub verbose: bool,

    /// Custom live-analysis log location table (default: config/log_locations.yaml)
    #[arg(long = "log-locations", value_name = "FILE", hide = true)]
    pub log_locations: Option<PathBuf>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct TimelineOptions {
    #[clap(flatten)]
    pub input: InputOption,

    #[clap(flatten)]
    pub general: GeneralOption,

    #[clap(flatten)]
    pub filter: FilterOption,

    #[clap(flatten)]
    pub output: OutputOption,

    #[clap(flatten)]
    pub common: CommonOptions,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Creates a DFIR timeline from Linux logs
    #[command(
        author = AUTHOR,
        version = FULL_VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  iwatobi dfir-timeline <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    DfirTimeline(TimelineOptions),

    /// Lists the output profiles
    #[command(
        author = AUTHOR,
        version = FULL_VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  iwatobi list-profiles [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ListProfiles {
        #[clap(flatten)]
        common: CommonOptions,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn negative_timezone_offset_is_accepted() {
        let cli = Cli::try_parse_from(["iwatobi", "dfir-timeline", "-f", "x.log", "-z", "-05:00"])
            .unwrap();
        let Commands::DfirTimeline(opts) = cli.cmd else {
            panic!()
        };
        assert!(matches!(
            opts.general.timezone,
            Some(TzAssumption::Fixed(_))
        ));
    }

    #[test]
    fn input_sources_are_mutually_exclusive_and_required() {
        assert!(Cli::try_parse_from(["iwatobi", "dfir-timeline", "-f", "a", "-d", "b"]).is_err());
        assert!(Cli::try_parse_from(["iwatobi", "dfir-timeline", "-f", "a", "-l"]).is_err());
        assert!(Cli::try_parse_from(["iwatobi", "dfir-timeline"]).is_err());
        assert!(Cli::try_parse_from(["iwatobi", "dfir-timeline", "-l"]).is_ok());
    }

    #[test]
    fn output_types_are_comma_separated() {
        let cli = Cli::try_parse_from([
            "iwatobi",
            "dfir-timeline",
            "-f",
            "a",
            "-o",
            "out",
            "-t",
            "csv,jsonl",
        ])
        .unwrap();
        let Commands::DfirTimeline(opts) = cli.cmd else {
            panic!()
        };
        assert_eq!(
            opts.output.output_types,
            vec![OutputFormat::Csv, OutputFormat::Jsonl]
        );
    }

    #[test]
    fn offsets() {
        assert_eq!(offset_to_seconds("30m"), Some(1800));
        assert_eq!(offset_to_seconds("1y"), Some(365 * 86400));
        assert_eq!(offset_to_seconds("3M"), Some(90 * 86400));
        assert_eq!(offset_to_seconds("x"), None);
        assert!(parse_level("HIGH").is_ok());
        assert!(parse_level("urgent").is_err());
    }
}
