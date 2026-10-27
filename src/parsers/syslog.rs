//! Syslog-family parser (RFC 3164, RFC 5424, rsyslog ISO, `journalctl -o short-iso`) and the
//! date-first "AppLog" shape (vsftpd.log, xferlog, clamd.log). See design §4.1 and amendments A1,
//! A3, A5 and A7.
//!
//! Every non-blank line becomes one event. A line that starts a record is classified into one of
//! the shapes below; anything else is a continuation event that borrows the previous entry's
//! timestamp. The syslog parser (`applog = false`) accepts the four syslog shapes, the AppLog
//! parser (`applog = true`) only the AppLog shape, so that `parse_line` produces an entry exactly
//! when the format's `matches_entry` says the line is one.
//!
//! | shape | example |
//! |---|---|
//! | RFC 3164 | `<34>Oct  6 17:39:01.123 2026 host proc[pid]: msg` (PRI, fraction and year optional) |
//! | rsyslog ISO / RFC 3339 | `2026-10-26T17:39:01.123456+09:00 host proc[pid]: msg` |
//! | `journalctl -o short-iso[-precise]` | `2026-10-26T17:32:36+0900 host proc[pid]: msg` |
//! | RFC 5424 | `<86>1 2026-10-26T08:44:06.000Z host app procid msgid [sd] msg` |
//! | AppLog | `Sun Oct 26 17:39:01 2026 [pid 1233] [ftpuser] FAIL LOGIN: ...` / `... -> msg` |

use super::{LineParser, ParseContext, continuation_event, timestamp};
use crate::event::{FieldValue, ParsedEvent};
use crate::logsource::LogSourceTag;
use crate::parsers::timestamp::Resolution;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use regex::Regex;
use std::sync::LazyLock;

/// RFC 3164 (amendment A5): optional `<PRI>`, space-padded day, optional fractional seconds,
/// optional 4-digit year. Whether the year group really is a year is decided in [`classify`].
static RFC3164_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:<(?P<pri>\d{1,3})>)?(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<hms>\d\d:\d\d:\d\d)(?P<frac>\.\d{1,9})?(?: (?P<year>\d{4}))? (?P<host>\S+) (?P<rest>.*)$",
    )
    .expect("RFC 3164 regex")
});

/// rsyslog high-precision / RFC 3339 and `journalctl -o short-iso[-precise]` (offset without a
/// colon). The zone is required (design §4.1): without it dpkg, MySQL and PostgreSQL logs, which
/// also start with an ISO date, would be read as syslog with words such as `install` as the
/// host. A host that is only digits (MySQL's thread id) is not a host either.
static ISO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:?\d\d)) (?P<host>\S*[^\d\s]\S*) (?P<rest>.*)$",
    )
    .expect("ISO syslog regex")
});

/// RFC 5424: `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]`.
/// The structured data is `-` or one or more `[SD-ID (SP PARAM-NAME="PARAM-VALUE")*]` elements
/// (amendment A5); after it one space, an optional UTF-8 BOM and at most one more space are
/// skipped before the message.
static RFC5424_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^<(?P<pri>\d{1,3})>(?P<ver>[1-9]\d{0,2}) (?P<ts>-|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[[^ =\]"]+(?: [^ =\]"]+="(?:[^"\\]|\\.)*")*\])+)(?: \x{FEFF}? ?(?P<msg>.*))?$"#,
    )
    .expect("RFC 5424 regex")
});

/// Design §4.1 process regex: `proc`, `proc[pid]`, `proc(ctx)[pid]`, then `:` and the message.
/// `(` is excluded from the name so that the optional parenthesised group is reachable.
static PROCESS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^\s:\[(]+(?:\([^)]*\))?)(?:\[(\d+)\])?:\s?(.*)$").expect("process regex")
});

/// AppLog shape (amendment A5): `Sun Oct 26 17:39:01 2026 rest`.
static APPLOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<wday>[A-Z][a-z]{2}) (?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<hms>\d\d:\d\d:\d\d) (?P<year>\d{4}) (?P<rest>.*)$",
    )
    .expect("AppLog regex")
});

/// vsftpd: `[pid N] [user] msg` (the user bracket is absent before login).
static VSFTPD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\[pid (\d+)\](?: \[([^\]]*)\])? ?(.*)$").expect("vsftpd regex"));

// Amendment A1: process name → service tags (case-insensitive, anchored).
static CRON_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(cron|crond|crontab|anacron)$").expect("cron regex"));
static SSHD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^sshd(-session|-auth)?$").expect("sshd regex"));
static AUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(su|sudo|login|systemd-logind|useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd|chpasswd|gdm.*|lightdm|sddm|polkitd|unix_chkpwd|pam_.*)$",
    )
    .expect("auth regex")
});
static CLAMAV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(clamd|freshclam|clamav.*)$").expect("clamav regex"));
static GUACAMOLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(guacd|guacamole.*)$").expect("guacamole regex"));
static PHP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^php(-fpm.*|-cgi.*|[0-9.]*)$").expect("php regex"));

/// Years a bare 4-digit token after the time may stand for (otherwise it is the host).
const YEAR_RANGE: std::ops::RangeInclusive<i32> = 1970..=2100;

/// Whether `line` starts a syslog record (any of the four syslog shapes).
pub fn matches_entry(line: &str) -> bool {
    classify(line).is_some()
}

/// Whether `line` starts a date-first application log record (`Sun Oct 26 17:39:01 2026 ...`).
pub fn matches_applog_entry(line: &str) -> bool {
    classify_applog(line).is_some()
}

/// Service tags implied by a syslog process name (amendment A1), e.g. `sshd-session` →
/// `[LINUX_SSHD, LINUX_AUTH]`, `crontab` → `[LINUX_CRON]`, `php-fpm8.3` → `[PHP_ERROR_LOG]`.
/// The most specific tag comes first (it becomes the event's primary log source). The name may
/// carry a path (`/usr/sbin/cron`) or a parenthesised context (`CRON(root)`); only the final path
/// component without that suffix is compared, case-insensitively.
pub fn service_tags_for_process(process: &str) -> Vec<LogSourceTag> {
    let name = process.trim();
    let name = name.rsplit('/').next().unwrap_or(name);
    let name = match name.find('(') {
        Some(idx) if name.ends_with(')') => &name[..idx],
        _ => name,
    };
    let name = name.trim_end_matches(':').trim();
    if name.is_empty() {
        return Vec::new();
    }
    if CRON_RE.is_match(name) {
        vec![LogSourceTag::LINUX_CRON]
    } else if SSHD_RE.is_match(name) {
        vec![LogSourceTag::LINUX_SSHD, LogSourceTag::LINUX_AUTH]
    } else if name.eq_ignore_ascii_case("sudo") {
        vec![LogSourceTag::LINUX_SUDO, LogSourceTag::LINUX_AUTH]
    } else if AUTH_RE.is_match(name) {
        vec![LogSourceTag::LINUX_AUTH]
    } else if name.eq_ignore_ascii_case("vsftpd") {
        vec![LogSourceTag::LINUX_VSFTPD]
    } else if CLAMAV_RE.is_match(name) {
        vec![LogSourceTag::LINUX_CLAMAV]
    } else if GUACAMOLE_RE.is_match(name) {
        vec![LogSourceTag::LINUX_GUACAMOLE]
    } else if PHP_RE.is_match(name) {
        if name.to_ascii_lowercase().starts_with("php-fpm") {
            // php-fpm logging to syslog / journald: its own messages are php-fpm log lines.
            vec![LogSourceTag::PHP_FPM, LogSourceTag::PHP_ERROR_LOG]
        } else {
            vec![LogSourceTag::PHP_ERROR_LOG]
        }
    } else {
        Vec::new()
    }
}

/// Clock fields of an RFC 3164 / AppLog timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Clock {
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    /// Nanoseconds; `>= 1_000_000_000` encodes a leap second (`:60`) the way chrono does.
    nanos: u32,
}

impl Clock {
    /// Parse `mon`, `day`, `HH:MM:SS` and an optional `.frac`, validating the ranges.
    fn parse(mon: &str, day: &str, hms: &str, frac: Option<&str>) -> Option<Clock> {
        let month = timestamp::month_from_abbr(mon)?;
        let day: u32 = day.parse().ok()?;
        if !(1..=31).contains(&day) {
            return None;
        }
        let mut parts = hms.split(':');
        let hour: u32 = parts.next()?.parse().ok()?;
        let minute: u32 = parts.next()?.parse().ok()?;
        let second: u32 = parts.next()?.parse().ok()?;
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        let (second, leap) = if second == 60 {
            (59, 1_000_000_000)
        } else {
            (second, 0)
        };
        Some(Clock {
            month,
            day,
            hour,
            minute,
            second,
            nanos: frac.map(timestamp::frac_to_nanos).unwrap_or(0) + leap,
        })
    }

    fn naive(&self, year: i32) -> Option<NaiveDateTime> {
        timestamp::naive_from_parts(
            year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.nanos,
        )
    }
}

/// A syslog line split into its header and the `rest` that carries `proc[pid]: msg`.
#[derive(Debug)]
enum Shape<'a> {
    Rfc3164 {
        pri: Option<u16>,
        clock: Clock,
        year: Option<i32>,
        /// `None` when the line has no hostname (`Oct 26 17:39:01 sshd[1]: msg`).
        host: Option<&'a str>,
        rest: &'a str,
    },
    Iso {
        pri: Option<u16>,
        ts: &'a str,
        host: &'a str,
        rest: &'a str,
    },
    Rfc5424 {
        pri: Option<u16>,
        ts: &'a str,
        host: &'a str,
        app: &'a str,
        procid: &'a str,
        msgid: &'a str,
        sd: &'a str,
        msg: Option<&'a str>,
    },
}

/// `<PRI>` value, `None` when out of range (0..=191).
fn parse_pri(s: Option<regex::Match<'_>>) -> Option<u16> {
    s.and_then(|m| m.as_str().parse::<u16>().ok())
        .filter(|p| *p <= 191)
}

/// Whether a token is the process token of a line (`sshd[1]:`, `kernel:`, `postfix/smtpd[1]:`):
/// it must end with the colon the process regex expects and carry nothing after it. An IPv6 host
/// such as `fe80::` does not qualify (the text after its first colon is not empty).
fn looks_like_process_token(token: &str) -> bool {
    PROCESS_RE
        .captures(token)
        .is_some_and(|c| c.get(3).is_none_or(|m| m.as_str().is_empty()))
}

/// Classify a line into one of the syslog shapes.
fn classify(line: &str) -> Option<Shape<'_>> {
    if let Some(c) = RFC5424_RE.captures(line) {
        return Some(Shape::Rfc5424 {
            pri: parse_pri(c.name("pri")),
            ts: c.name("ts")?.as_str(),
            host: c.name("host")?.as_str(),
            app: c.name("app")?.as_str(),
            procid: c.name("procid")?.as_str(),
            msgid: c.name("msgid")?.as_str(),
            sd: c.name("sd")?.as_str(),
            msg: c.name("msg").map(|m| m.as_str()),
        });
    }
    if let Some(c) = ISO_RE.captures(line) {
        return Some(Shape::Iso {
            pri: parse_pri(c.name("pri")),
            ts: c.name("ts")?.as_str(),
            host: c.name("host")?.as_str(),
            rest: c.name("rest")?.as_str(),
        });
    }
    let c = RFC3164_RE.captures(line)?;
    let clock = Clock::parse(
        c.name("mon")?.as_str(),
        c.name("day")?.as_str(),
        c.name("hms")?.as_str(),
        c.name("frac").map(|m| m.as_str()),
    )?;
    let host_m = c.name("host")?;
    let rest_m = c.name("rest")?;
    let mut year = None;
    let mut host = Some(host_m.as_str());
    let mut rest = rest_m.as_str();
    if let Some(year_m) = c.name("year") {
        let plausible: Option<i32> = year_m
            .as_str()
            .parse()
            .ok()
            .filter(|y| YEAR_RANGE.contains(y));
        match plausible {
            // `Oct 26 17:55:00 2026 host sudo: ...`: a plausible year followed by a host token
            // that is not itself the process token.
            Some(y) if !looks_like_process_token(host_m.as_str()) => year = Some(y),
            // `Oct 26 17:39:01 2026 sshd[1]: msg` or `... 0042 host msg`: the token is the host.
            _ => {
                host = Some(year_m.as_str());
                // the regex guarantees exactly one space between the two tokens
                rest = &line[host_m.start()..];
            }
        }
    } else if looks_like_process_token(host_m.as_str()) {
        // `Oct 26 17:39:01 sshd[1]: msg`: a log written without a hostname.
        host = None;
        rest = &line[host_m.start()..];
    } else if host_m.as_str() == ":" {
        // sudoers `logfile=`: `Oct 26 17:46:00 : user : TTY=pts/0 ; ...` has no host.
        host = None;
    }
    Some(Shape::Rfc3164 {
        pri: parse_pri(c.name("pri")),
        clock,
        year,
        host,
        rest,
    })
}

/// The AppLog shape: clock, year and the rest of the line.
fn classify_applog(line: &str) -> Option<(Clock, i32, &str)> {
    let c = APPLOG_RE.captures(line)?;
    const WEEKDAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let wday = c.name("wday")?.as_str().to_ascii_lowercase();
    if !WEEKDAYS.contains(&wday.as_str()) {
        return None;
    }
    let clock = Clock::parse(
        c.name("mon")?.as_str(),
        c.name("day")?.as_str(),
        c.name("hms")?.as_str(),
        None,
    )?;
    let year: i32 = c.name("year")?.as_str().parse().ok()?;
    Some((clock, year, c.name("rest")?.as_str()))
}

/// Split `rest` into `(process, pid, message)` with the §4.1 process regex. When no process can
/// be split the whole `rest` is the message. Surrounding whitespace of the message is dropped
/// (`sudo:     user : TTY=...` logs the user name padded).
fn split_process(rest: &str) -> (Option<&str>, Option<i64>, &str) {
    match PROCESS_RE.captures(rest) {
        Some(c) => {
            let process = c.get(1).map(|m| m.as_str());
            let pid = c.get(2).and_then(|m| m.as_str().parse::<i64>().ok());
            let message = c.get(3).map(|m| m.as_str().trim()).unwrap_or("");
            (process, pid, message)
        }
        None => (None, None, rest.trim()),
    }
}

/// `-` (the syslog nil value) → `None`.
fn nil_to_none(s: &str) -> Option<&str> {
    if s.is_empty() || s == "-" {
        None
    } else {
        Some(s)
    }
}

/// The header fields every syslog shape yields.
struct Header<'a> {
    pri: Option<u16>,
    host: Option<&'a str>,
    process: Option<String>,
    pid: FieldValue,
    message: String,
    /// RFC 5424 only: `msgid` and `structured_data`.
    rfc5424: Option<(FieldValue, FieldValue)>,
}

pub struct SyslogParser {
    ctx: ParseContext,
    applog: bool,
    last_ts: Option<DateTime<FixedOffset>>,
    /// Amendment A7: a DST ambiguity/gap is reported once per file.
    warned_resolution: bool,
    /// `process` of AppLog events: the service the file belongs to.
    applog_process: Option<String>,
}

impl SyslogParser {
    pub fn new(ctx: ParseContext, applog: bool) -> Self {
        let applog_process = applog_process_name(&ctx);
        Self {
            ctx,
            applog,
            last_ts: None,
            warned_resolution: false,
            applog_process,
        }
    }

    /// Resolve a naive time in the assumed zone, reporting a DST ambiguity once per file.
    fn resolve(&mut self, naive: NaiveDateTime) -> DateTime<FixedOffset> {
        let (dt, res) = timestamp::resolve_naive(naive, &self.ctx.tz);
        if res != Resolution::Exact && !self.warned_resolution {
            self.warned_resolution = true;
            let what = match res {
                Resolution::Ambiguous => {
                    "is ambiguous (DST transition); the earlier instant was used"
                }
                _ => "does not exist (DST gap); it was moved forward one hour",
            };
            crate::errorlog::log_warn(&format!(
                "{}: the local time {naive} {what} in timezone {}. Use -z to set the zone of the log.",
                self.ctx.display_name, self.ctx.tz
            ));
        }
        dt
    }

    /// Set the event timestamp: `Some` → the line's own time; `None` → borrow the previous one.
    fn set_timestamp(&mut self, ev: &mut ParsedEvent, ts: Option<DateTime<FixedOffset>>) {
        match ts {
            Some(t) => {
                ev.timestamp = Some(t);
                ev.timestamp_inferred = false;
                self.last_ts = Some(t);
            }
            None => {
                ev.timestamp = self.last_ts;
                ev.timestamp_inferred = self.last_ts.is_some();
            }
        }
    }

    /// Timestamp of an RFC 3164 line: the year is written, or inferred from the file (A7).
    fn rfc3164_time(&mut self, clock: &Clock, year: Option<i32>) -> Option<DateTime<FixedOffset>> {
        let year = year.unwrap_or_else(|| {
            timestamp::infer_year(
                clock.month,
                clock.day,
                self.ctx.year_hint,
                self.ctx
                    .mtime
                    .map(|t| timestamp::local_date(t, &self.ctx.tz)),
            )
        });
        let naive = clock.naive(year)?;
        Some(self.resolve(naive))
    }

    /// Timestamp of an ISO-like token: its own zone when it has one, else the assumed zone.
    /// The boolean is `tz_explicit`.
    fn iso_time(&mut self, ts: &str) -> Option<(DateTime<FixedOffset>, bool)> {
        if let Some(dt) = timestamp::parse_iso_with_zone(ts) {
            return Some((dt, true));
        }
        let naive = timestamp::parse_iso_naive(ts)?;
        Some((self.resolve(naive), false))
    }

    /// The tag shown in the `LogSource` column: process-derived, else file-derived, else syslog.
    fn primary_for(&self, process_tags: &[LogSourceTag]) -> LogSourceTag {
        process_tags
            .first()
            .or(self.ctx.hints.service_tags.first())
            .copied()
            .unwrap_or(LogSourceTag::LINUX_SYSLOG)
    }

    /// Build the event of a syslog-shaped line.
    fn syslog_event(&mut self, line: &str, shape: Shape<'_>) -> ParsedEvent {
        let mut ev = ParsedEvent::new(line, &LogSourceTag::LINUX_SYSLOG);
        let header = match shape {
            Shape::Rfc3164 {
                pri,
                clock,
                year,
                host,
                rest,
            } => {
                let ts = self.rfc3164_time(&clock, year);
                self.set_timestamp(&mut ev, ts);
                ev.tz_explicit = false;
                let (process, pid, message) = split_process(rest);
                Header {
                    pri,
                    host,
                    process: process.map(str::to_string),
                    pid: FieldValue::from(pid),
                    message: message.to_string(),
                    rfc5424: None,
                }
            }
            Shape::Iso {
                pri,
                ts,
                host,
                rest,
            } => {
                let parsed = self.iso_time(ts);
                self.set_timestamp(&mut ev, parsed.map(|(dt, _)| dt));
                ev.tz_explicit = parsed.is_some_and(|(_, explicit)| explicit);
                let (process, pid, message) = split_process(rest);
                Header {
                    pri,
                    host: Some(host),
                    process: process.map(str::to_string),
                    pid: FieldValue::from(pid),
                    message: message.to_string(),
                    rfc5424: None,
                }
            }
            Shape::Rfc5424 {
                pri,
                ts,
                host,
                app,
                procid,
                msgid,
                sd,
                msg,
            } => {
                let parsed = if ts == "-" { None } else { self.iso_time(ts) };
                self.set_timestamp(&mut ev, parsed.map(|(dt, _)| dt));
                ev.tz_explicit = parsed.is_some_and(|(_, explicit)| explicit);
                let pid = match nil_to_none(procid) {
                    None => FieldValue::Null,
                    Some(id) => id
                        .parse::<i64>()
                        .map(FieldValue::Int)
                        .unwrap_or_else(|_| FieldValue::Str(id.to_string())),
                };
                Header {
                    pri,
                    host: Some(host),
                    process: nil_to_none(app).map(str::to_string),
                    pid,
                    message: msg.unwrap_or("").trim_end().to_string(),
                    rfc5424: Some((
                        FieldValue::from(nil_to_none(msgid)),
                        FieldValue::from(nil_to_none(sd)),
                    )),
                }
            }
        };
        ev.hostname = header.host.and_then(nil_to_none).map(str::to_string);
        ev.push("process", header.process.clone());
        ev.push("pid", header.pid);
        ev.push("message", header.message.as_str());
        if let Some(pri) = header.pri {
            ev.push("facility", i64::from(pri / 8));
            ev.push("severity", i64::from(pri % 8));
        }
        if let Some((msgid, sd)) = header.rfc5424 {
            ev.push("msgid", msgid);
            ev.push("structured_data", sd);
        }
        let process_tags = header
            .process
            .as_deref()
            .map(service_tags_for_process)
            .unwrap_or_default();
        ev.add_tags(&self.ctx.hints.service_tags);
        ev.add_tags(&process_tags);
        super::php::tag_php_message(&mut ev, &header.message);
        ev.set_primary(self.primary_for(&process_tags));
        self.ctx.finish(&mut ev);
        ev
    }

    /// Tags of an AppLog event: the file-derived service tags, else `linux/syslog`.
    fn applog_tags(&self) -> (LogSourceTag, &[LogSourceTag]) {
        match self.ctx.hints.service_tags.split_first() {
            Some((first, others)) => (*first, others),
            None => (LogSourceTag::LINUX_SYSLOG, &[]),
        }
    }

    /// Build the event of an AppLog-shaped line.
    fn applog_event(&mut self, line: &str, clock: Clock, year: i32, rest: &str) -> ParsedEvent {
        let (primary, others) = self.applog_tags();
        let mut ev = ParsedEvent::new(line, &primary);
        ev.add_tags(others);
        let ts = clock.naive(year).map(|naive| self.resolve(naive));
        self.set_timestamp(&mut ev, ts);
        ev.tz_explicit = false;
        ev.push("process", self.applog_process.clone());
        let message: &str = if let Some(c) = VSFTPD_RE.captures(rest) {
            // vsftpd: `[pid N] [user] msg`
            let pid = c.get(1).and_then(|m| m.as_str().parse::<i64>().ok());
            let user = c.get(2).map(|m| m.as_str()).filter(|u| !u.is_empty());
            ev.push("pid", pid);
            ev.push("user", user);
            c.get(3).map(|m| m.as_str().trim()).unwrap_or("")
        } else if let Some(msg) = rest.strip_prefix("->") {
            // clamd / freshclam: `-> msg`
            ev.push("pid", FieldValue::Null);
            msg.trim()
        } else {
            // xferlog and anything else
            ev.push("pid", FieldValue::Null);
            rest.trim()
        };
        ev.push("message", message);
        super::php::tag_php_message(&mut ev, message);
        self.ctx.finish(&mut ev);
        ev
    }

    /// A line that starts no record: same tags as the entries, timestamp borrowed.
    fn continuation(&self, line: &str) -> ParsedEvent {
        let mut ev = if self.applog {
            let (primary, others) = self.applog_tags();
            continuation_event(line, &primary, others, self.last_ts)
        } else {
            let mut ev = continuation_event(
                line,
                &LogSourceTag::LINUX_SYSLOG,
                &self.ctx.hints.service_tags,
                self.last_ts,
            );
            ev.set_primary(self.primary_for(&[]));
            ev
        };
        super::php::tag_php_message(&mut ev, line.trim());
        self.ctx.finish(&mut ev);
        ev
    }
}

/// `process` of AppLog events: `vsftpd.log.1` → `vsftpd`, `clamd.log` → `clamd`, `xferlog` →
/// `xferlog`; otherwise the rotation-free file name; `None` when the path has no file name.
fn applog_process_name(ctx: &ParseContext) -> Option<String> {
    let file = ctx.path.file_name()?.to_str()?;
    let base = super::rotation_free_name(&file.to_ascii_lowercase());
    for service in ["vsftpd", "freshclam", "clamd", "xferlog"] {
        if base.starts_with(service) {
            return Some(service.to_string());
        }
    }
    let base = super::rotation_free_name(file);
    if base.is_empty() { None } else { Some(base) }
}

impl LineParser for SyslogParser {
    fn parse_line(&mut self, line: &str) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            return None;
        }
        if self.applog {
            if let Some((clock, year, rest)) = classify_applog(line) {
                return Some(self.applog_event(line, clock, year, rest));
            }
        } else if let Some(shape) = classify(line) {
            return Some(self.syslog_event(line, shape));
        }
        Some(self.continuation(line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logsource::LogSourceSpec;
    use crate::parsers::{LogFormat, TzAssumption, parser_for, path_hints};
    use chrono::{TimeZone, Utc};
    use std::path::Path;

    const SYSLOG: LogSourceTag = LogSourceTag::LINUX_SYSLOG;
    const AUTH: LogSourceTag = LogSourceTag::LINUX_AUTH;
    const SSHD: LogSourceTag = LogSourceTag::LINUX_SSHD;
    const CRON: LogSourceTag = LogSourceTag::LINUX_CRON;
    const SUDO: LogSourceTag = LogSourceTag::LINUX_SUDO;
    const VSFTPD: LogSourceTag = LogSourceTag::LINUX_VSFTPD;
    const CLAMAV: LogSourceTag = LogSourceTag::LINUX_CLAMAV;
    const GUACAMOLE: LogSourceTag = LogSourceTag::LINUX_GUACAMOLE;
    const PHP: LogSourceTag = LogSourceTag::PHP_ERROR_LOG;

    fn jst() -> TzAssumption {
        TzAssumption::Fixed(FixedOffset::east_opt(9 * 3600).unwrap())
    }

    /// A context with a fixed year hint and mtime, so that year inference is deterministic
    /// whatever the checkout date of the fixtures is.
    fn ctx_for(path: &str, tz: TzAssumption) -> ParseContext {
        let p = Path::new(path);
        ParseContext {
            path: p.to_path_buf(),
            display_name: path.to_string(),
            tz,
            year_hint: 2026,
            mtime: Some(Utc.with_ymd_and_hms(2026, 10, 27, 0, 0, 0).unwrap()),
            hints: path_hints(p),
            hostname_hint: None,
            extra_tags: Vec::new(),
        }
    }

    fn fixture_path(name: &str) -> String {
        format!("{}/test_files/linux/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn fixture_lines(name: &str) -> Vec<String> {
        std::fs::read_to_string(fixture_path(name))
            .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn syslog_parser(path: &str) -> SyslogParser {
        SyslogParser::new(ctx_for(path, jst()), false)
    }

    fn applog_parser(path: &str) -> SyslogParser {
        SyslogParser::new(ctx_for(path, jst()), true)
    }

    fn parse_fixture(name: &str, applog: bool) -> Vec<ParsedEvent> {
        let path = fixture_path(name);
        let mut parser = SyslogParser::new(ctx_for(&path, jst()), applog);
        fixture_lines(name)
            .iter()
            .map(|l| parser.parse_line(l).expect("non-blank line"))
            .collect()
    }

    fn one(parser: &mut SyslogParser, line: &str) -> ParsedEvent {
        parser.parse_line(line).expect("non-blank line")
    }

    fn ts(ev: &ParsedEvent) -> String {
        ev.timestamp.expect("timestamp").to_rfc3339()
    }

    fn s<'a>(ev: &'a ParsedEvent, key: &str) -> &'a str {
        ev.field_str(key)
            .unwrap_or_else(|| panic!("field {key} is not a string: {:?}", ev.field(key)))
    }

    fn keys(fields: &[(String, FieldValue)]) -> Vec<&str> {
        fields.iter().map(|(k, _)| k.as_str()).collect()
    }

    // ----------------------------------------------------------------------------------------
    // service_tags_for_process (amendment A1)
    // ----------------------------------------------------------------------------------------

    #[test]
    fn service_tags_cron_family() {
        for name in [
            "cron", "crond", "crontab", "anacron", "CRON", "CROND", "Anacron",
        ] {
            assert_eq!(service_tags_for_process(name), vec![CRON], "{name}");
        }
        assert!(service_tags_for_process("cronie").is_empty());
        assert!(service_tags_for_process("run-parts").is_empty());
    }

    #[test]
    fn service_tags_sshd_variants_are_sshd_and_auth() {
        for name in ["sshd", "sshd-session", "sshd-auth", "SSHD", "Sshd-Session"] {
            assert_eq!(service_tags_for_process(name), vec![SSHD, AUTH], "{name}");
        }
        assert!(service_tags_for_process("sshd2").is_empty());
        assert!(service_tags_for_process("sshd-sessionx").is_empty());
        assert!(service_tags_for_process("ssh").is_empty());
    }

    #[test]
    fn service_tags_sudo_is_sudo_and_auth() {
        assert_eq!(service_tags_for_process("sudo"), vec![SUDO, AUTH]);
        assert_eq!(service_tags_for_process("SUDO"), vec![SUDO, AUTH]);
        assert!(service_tags_for_process("sudoers").is_empty());
    }

    #[test]
    fn service_tags_auth_set() {
        for name in [
            "su",
            "login",
            "systemd-logind",
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "groupmod",
            "groupdel",
            "passwd",
            "chpasswd",
            "gdm",
            "gdm3",
            "gdm-session-worker",
            "lightdm",
            "sddm",
            "polkitd",
            "unix_chkpwd",
            "pam_unix",
            "pam_systemd",
            "Login",
            "SYSTEMD-LOGIND",
        ] {
            assert_eq!(service_tags_for_process(name), vec![AUTH], "{name}");
        }
        assert!(service_tags_for_process("sulogin").is_empty());
        assert!(service_tags_for_process("systemd").is_empty());
    }

    #[test]
    fn service_tags_other_services() {
        assert_eq!(service_tags_for_process("vsftpd"), vec![VSFTPD]);
        assert_eq!(service_tags_for_process("VSFTPD"), vec![VSFTPD]);
        for name in [
            "clamd",
            "freshclam",
            "clamav-daemon",
            "clamav-milter",
            "ClamD",
        ] {
            assert_eq!(service_tags_for_process(name), vec![CLAMAV], "{name}");
        }
        for name in ["guacd", "guacamole", "guacamole-server"] {
            assert_eq!(service_tags_for_process(name), vec![GUACAMOLE], "{name}");
        }
        for name in ["php", "php8.3", "php83", "php-cgi", "php-cgi7.4"] {
            assert_eq!(service_tags_for_process(name), vec![PHP], "{name}");
        }
        // php-fpm logging through syslog writes php-fpm log lines
        for name in ["php-fpm", "php-fpm8.3", "PHP-FPM"] {
            assert_eq!(
                service_tags_for_process(name),
                vec![LogSourceTag::PHP_FPM, PHP],
                "{name}"
            );
        }
        assert!(service_tags_for_process("phpmyadmin").is_empty());
    }

    #[test]
    fn service_tags_compare_the_final_path_component_without_context() {
        assert_eq!(service_tags_for_process("/usr/sbin/cron"), vec![CRON]);
        assert_eq!(service_tags_for_process("/usr/sbin/sshd"), vec![SSHD, AUTH]);
        assert_eq!(service_tags_for_process("CRON(root)"), vec![CRON]);
        assert_eq!(service_tags_for_process("sudo:"), vec![SUDO, AUTH]);
        assert_eq!(service_tags_for_process("  crond  "), vec![CRON]);
        // the final component of `postfix/smtpd` is `smtpd`
        assert!(service_tags_for_process("postfix/smtpd").is_empty());
    }

    #[test]
    fn service_tags_none_for_unknown_processes() {
        for name in [
            "systemd",
            "named",
            "rsyslogd",
            "kernel",
            "iptables.init",
            "",
            "/",
            "()",
            "   ",
        ] {
            assert!(service_tags_for_process(name).is_empty(), "{name:?}");
        }
    }

    // ----------------------------------------------------------------------------------------
    // matches_entry / matches_applog_entry
    // ----------------------------------------------------------------------------------------

    #[test]
    fn matches_entry_accepts_every_syslog_fixture_line() {
        for name in [
            "syslog",
            "auth.log",
            "secure",
            "cron",
            "rsyslog-iso.log",
            "rfc5424.log",
            "journalctl-short-iso.log",
        ] {
            let lines = fixture_lines(name);
            assert!(!lines.is_empty(), "{name} is empty");
            for line in lines {
                assert!(matches_entry(&line), "{name}: {line}");
                assert!(LogFormat::Syslog.matches_entry(&line), "{name}: {line}");
                assert!(!matches_applog_entry(&line), "{name}: {line}");
            }
        }
    }

    #[test]
    fn matches_entry_rejects_non_entries() {
        for line in [
            "",
            "   ",
            "sh: 1: wget: not found",
            " Oct 26 17:39:01 host proc: indented",
            "Sun Oct 26 17:39:01 2026 [pid 1234] CONNECT: Client \"::ffff:203.0.113.40\"",
            "Oct 26 17:39:01",
            "Oct 26 17:39:01 host",
            "Foo 26 17:39:01 host proc: bad month",
            "Oct 32 17:39:01 host proc: bad day",
            "Oct 0 17:39:01 host proc: bad day",
            "Oct 26 25:39:01 host proc: bad hour",
            "Oct 26 17:60:01 host proc: bad minute",
            "Oct 26 17:39:61 host proc: bad second",
            "203.0.113.5 - - [26/Oct/2026:17:39:01 +0900] \"GET / HTTP/1.1\" 200 12",
            "[Sat Oct 24 15:35:39.379473 2026] [core:notice] [pid 1:tid 1] AH00094: Command line",
            "2026/10/24 15:35:39 [error] 1234#1234: *5 upstream prematurely closed connection",
            "[24-Oct-2026 15:35:33 UTC] PHP Fatal error:  Allowed memory size",
            "<86>1 2026-10-26T08:44:06Z host app",
            "#0 {main}",
            "-- Reboot --",
        ] {
            assert!(!matches_entry(line), "{line}");
        }
    }

    #[test]
    fn matches_applog_entry_shapes() {
        for line in [
            "Sun Oct 26 17:39:01 2026 [pid 1234] CONNECT: Client \"::ffff:203.0.113.40\"",
            "Sun Oct 26 17:40:00 2026 -> +++ Started at Sun Oct 26 17:40:00 2026",
            "Mon Oct  6 17:40:00 2026 1 203.0.113.40 1024 /pub/file.bin b _ o r ftpuser ftp 0 * c",
        ] {
            assert!(matches_applog_entry(line), "{line}");
            assert!(LogFormat::AppLog.matches_entry(line), "{line}");
            assert!(!matches_entry(line), "{line}");
        }
        for line in [
            "",
            "Oct 26 17:39:01 host proc: syslog",
            "Xyz Oct 26 17:39:01 2026 bad weekday",
            "Sun Foo 26 17:39:01 2026 bad month",
            "Sun Oct 26 17:39:01 2026",
            "Sun Oct 26 17:39:01 bad year",
            "Sun Oct 26 24:00:00 2026 bad hour",
            "-> Received POSIX_FADVISE",
            "[pid 1234] CONNECT: Client",
        ] {
            assert!(!matches_applog_entry(line), "{line}");
        }
    }

    // ----------------------------------------------------------------------------------------
    // the syslog fixture, line by line
    // ----------------------------------------------------------------------------------------

    /// `(timestamp, process, pid, message, primary)` of one fixture line.
    type Expected<'a> = (&'a str, Option<&'a str>, Option<i64>, &'a str, &'a str);

    #[test]
    fn syslog_fixture_lines_parse_exactly() {
        let events = parse_fixture("syslog", false);
        assert_eq!(events.len(), 28);
        let expected: [Expected; 28] = [
            (
                "2026-10-26T17:39:01+09:00",
                Some("CRON"),
                Some(12345),
                "(root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
                "linux/cron",
            ),
            (
                "2026-10-26T17:39:30+09:00",
                Some("systemd"),
                Some(1),
                "Started session-12.scope - Session 12 of User user.",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:40:12+09:00",
                Some("crontab"),
                Some(12399),
                "(user) LIST (user)",
                "linux/cron",
            ),
            (
                "2026-10-26T17:40:15+09:00",
                Some("crontab"),
                Some(12399),
                "(user) BEGIN EDIT (user)",
                "linux/cron",
            ),
            (
                "2026-10-26T17:40:40+09:00",
                Some("crontab"),
                Some(12399),
                "(user) REPLACE (user)",
                "linux/cron",
            ),
            (
                "2026-10-26T17:40:40+09:00",
                Some("crontab"),
                Some(12399),
                "(user) END EDIT (user)",
                "linux/cron",
            ),
            (
                "2026-10-26T17:41:00+09:00",
                Some("systemd"),
                Some(1),
                "Stopping firewalld.service - firewalld - dynamic firewall daemon...",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:41:01+09:00",
                Some("systemd"),
                Some(1),
                "firewalld.service: Deactivated successfully.",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:41:05+09:00",
                Some("iptables.init"),
                Some(12500),
                "Stopping iptables: [  OK  ]",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:42:30+09:00",
                Some("named"),
                Some(2210),
                "client @0x7f3c0c0a1234 203.0.113.9#5353 (example.com): zone example.com/IN: denied AXFR from 203.0.113.9#5353",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:42:31+09:00",
                Some("named"),
                Some(2210),
                "dropping source port zero packet from 203.0.113.9#0",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:42:35+09:00",
                Some("named"),
                Some(2210),
                "resolver priming query complete: success",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:43:00+09:00",
                Some("named"),
                Some(2210),
                "exiting (due to fatal error)",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:44:00+09:00",
                Some("sshd"),
                Some(13001),
                "Accepted publickey for user from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijk",
                "linux/sshd",
            ),
            (
                "2026-10-26T17:44:05+09:00",
                Some("sshd"),
                Some(13002),
                "fatal: buffer_get_string: bad string",
                "linux/sshd",
            ),
            (
                "2026-10-26T17:44:06+09:00",
                Some("sshd"),
                Some(13003),
                "Corrupted MAC on input.",
                "linux/sshd",
            ),
            (
                "2026-10-26T17:45:00+09:00",
                Some("sudo"),
                None,
                "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update",
                "linux/sudo",
            ),
            (
                "2026-10-26T17:45:00+09:00",
                Some("sudo"),
                None,
                "pam_unix(sudo:session): session opened for user root(uid=0) by user(uid=1000)",
                "linux/sudo",
            ),
            (
                "2026-10-26T17:46:00+09:00",
                Some("kernel"),
                None,
                "[12345.678901] usb 1-1: new high-speed USB device number 5 using xhci_hcd",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:47:00+09:00",
                Some("systemd-logind"),
                Some(800),
                "New session 13 of user user.",
                "linux/auth",
            ),
            (
                "2026-10-26T17:49:00+09:00",
                Some("rsyslogd"),
                None,
                r#"[origin software="rsyslogd" swVersion="8.2412.0" x-pid="700" x-info="https://www.rsyslog.com"] start"#,
                "linux/syslog",
            ),
            (
                "2026-10-26T17:50:00+09:00",
                Some("postfix/smtpd"),
                Some(15000),
                "connect from unknown[203.0.113.77]",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:50:01+09:00",
                Some("postfix/smtpd"),
                Some(15000),
                "disconnect from unknown[203.0.113.77] ehlo=1 quit=1 commands=2",
                "linux/syslog",
            ),
            (
                "2026-10-26T17:52:00+09:00",
                Some("sshd-session"),
                Some(13100),
                "error: Corrupted MAC on input.",
                "linux/sshd",
            ),
            (
                "2026-10-26T17:52:01.123456+09:00",
                Some("sshd-session"),
                Some(13100),
                "Connection closed by 203.0.113.5 port 51300 [preauth]",
                "linux/sshd",
            ),
            (
                "2026-10-26T17:53:00+09:00",
                Some("php"),
                Some(14100),
                "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
                "php/error_log",
            ),
            (
                "2026-10-06T17:54:00+09:00",
                Some("systemd-logind"),
                Some(800),
                "Removed session 13.",
                "linux/auth",
            ),
            (
                "2026-10-26T17:55:00+09:00",
                Some("sudo"),
                None,
                "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/systemctl stop firewalld",
                "linux/sudo",
            ),
        ];
        let lines = fixture_lines("syslog");
        for (i, (exp, ev)) in expected.iter().zip(&events).enumerate() {
            let n = i + 1;
            assert_eq!(ts(ev), exp.0, "line {n}: timestamp");
            assert!(!ev.timestamp_inferred, "line {n}: own timestamp");
            assert!(!ev.tz_explicit, "line {n}: RFC 3164 has no zone");
            assert_eq!(
                ev.hostname.as_deref(),
                Some("kali-linux-2025-2"),
                "line {n}"
            );
            assert_eq!(
                ev.field("process"),
                Some(&FieldValue::from(exp.1)),
                "line {n}"
            );
            assert_eq!(ev.field("pid"), Some(&FieldValue::from(exp.2)), "line {n}");
            assert_eq!(s(ev, "message"), exp.3, "line {n}: message");
            assert_eq!(ev.primary_logsource, exp.4, "line {n}: primary");
            assert_eq!(ev.raw, lines[i], "line {n}: raw");
            assert_eq!(
                keys(&ev.fields[..3]),
                ["process", "pid", "message"],
                "line {n}"
            );
            // The php[14100] line carries the PHP message fields (php_type, php_message, file,
            // line) that the PHP detector adds; every other line has no PRI and no other fields.
            if ev.tags.contains(&LogSourceTag::PHP_ERROR_LOG) {
                assert_eq!(
                    keys(&ev.fields[3..]),
                    ["php_type", "php_message", "file", "line"],
                    "line {n}: PHP fields"
                );
            } else {
                assert_eq!(ev.fields.len(), 3, "line {n}: no PRI, no other fields");
            }
            assert_eq!(ev.tags[0], SYSLOG, "line {n}: first tag is syslog");
        }
    }

    #[test]
    fn syslog_fixture_tag_sets() {
        let events = parse_fixture("syslog", false);
        // crontab[12399]: (user) REPLACE (user)
        assert_eq!(events[4].tags, vec![SYSLOG, CRON]);
        assert_eq!(events[4].primary_logsource, "linux/cron");
        // sshd-session[13100]: error: Corrupted MAC on input.
        assert_eq!(events[23].tags, vec![SYSLOG, SSHD, AUTH]);
        // sudo: both sudo and auth
        assert_eq!(events[16].tags, vec![SYSLOG, SUDO, AUTH]);
        // systemd: only syslog
        assert_eq!(events[1].tags, vec![SYSLOG]);
        // php[14100]: tagged from the process name (A1), php.rs not needed
        assert_eq!(events[25].tags, vec![SYSLOG, PHP]);
        assert_eq!(events[25].primary_logsource, "php/error_log");
        // kernel keeps process = kernel and the bracketed uptime in the message
        assert_eq!(s(&events[18], "process"), "kernel");
        assert!(s(&events[18], "message").starts_with("[12345.678901] usb"));
    }

    #[test]
    fn sudo_without_pid_and_padded_user() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(
            &mut p,
            "Oct 26 17:45:00 host sudo:     user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update",
        );
        assert_eq!(s(&ev, "process"), "sudo");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
        assert!(s(&ev, "message").starts_with("user : TTY"));
        assert_eq!(ev.primary_logsource, "linux/sudo");
        assert_eq!(ev.tags, vec![SYSLOG, SUDO, AUTH]);
    }

    #[test]
    fn fractional_seconds_and_space_padded_day() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(
            &mut p,
            "Oct 26 17:52:01.123456 host sshd-session[13100]: Connection closed",
        );
        assert_eq!(ts(&ev), "2026-10-26T17:52:01.123456+09:00");
        assert_eq!(ev.timestamp.unwrap().timestamp_subsec_nanos(), 123_456_000);
        let ev = one(
            &mut p,
            "Oct  6 17:54:00 host systemd-logind[800]: Removed session 13.",
        );
        assert_eq!(ts(&ev), "2026-10-06T17:54:00+09:00");
        let ev = one(&mut p, "Oct 26 17:52:01.5 host proc: m");
        assert_eq!(ts(&ev), "2026-10-26T17:52:01.500+09:00");
        let ev = one(&mut p, "Oct 26 17:52:01.123456789 host proc: m");
        assert_eq!(ts(&ev), "2026-10-26T17:52:01.123456789+09:00");
    }

    #[test]
    fn four_digit_year_after_the_time_is_used_when_a_host_follows() {
        let mut p = SyslogParser::new(ctx_for("/var/log/syslog", jst()), false);
        p.ctx.year_hint = 2031; // must be ignored: the line carries its year
        let ev = one(
            &mut p,
            "Oct 26 17:55:00 2026 host sudo:     user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/systemctl stop firewalld",
        );
        assert_eq!(ts(&ev), "2026-10-26T17:55:00+09:00");
        assert_eq!(ev.hostname.as_deref(), Some("host"));
        assert_eq!(s(&ev, "process"), "sudo");
        assert!(s(&ev, "message").starts_with("user : TTY=pts/0"));
        // with fractional seconds and a PRI as well
        let ev = one(&mut p, "<13>Oct 26 17:52:01.5 2025 host proc[7]: m");
        assert_eq!(ts(&ev), "2025-10-26T17:52:01.500+09:00");
        assert_eq!(ev.hostname.as_deref(), Some("host"));
        assert_eq!(s(&ev, "process"), "proc");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(7)));
        assert_eq!(s(&ev, "message"), "m");
    }

    #[test]
    fn host_literally_named_2026_without_a_year_keeps_the_host() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 2026 sshd[1]: Accepted publickey for user",
        );
        assert_eq!(ev.hostname.as_deref(), Some("2026"));
        assert_eq!(s(&ev, "process"), "sshd");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(1)));
        assert_eq!(s(&ev, "message"), "Accepted publickey for user");
        assert_eq!(
            ts(&ev),
            "2026-10-26T17:39:01+09:00",
            "year inferred from the context"
        );
        assert_eq!(ev.primary_logsource, "linux/sshd");
        let ev = one(&mut p, "Oct 26 17:39:01 2026 kernel: [1.0] usb");
        assert_eq!(ev.hostname.as_deref(), Some("2026"));
        assert_eq!(s(&ev, "process"), "kernel");
        assert_eq!(s(&ev, "message"), "[1.0] usb");
    }

    #[test]
    fn four_digit_token_outside_the_year_range_is_the_host() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "Oct 26 17:39:01 0042 host message");
        assert_eq!(ev.hostname.as_deref(), Some("0042"));
        assert_eq!(ev.field("process"), Some(&FieldValue::Null));
        assert_eq!(s(&ev, "message"), "host message");
        let ev = one(&mut p, "Oct 26 17:39:01 2101 proc: m");
        assert_eq!(ev.hostname.as_deref(), Some("2101"));
        assert_eq!(s(&ev, "process"), "proc");
        // a 4-digit token followed by a single token is the host, the token the message
        let ev = one(&mut p, "Oct 26 17:39:01 2026 reboot");
        assert_eq!(ev.hostname.as_deref(), Some("2026"));
        assert_eq!(s(&ev, "message"), "reboot");
    }

    #[test]
    fn line_without_a_hostname_still_splits_the_process() {
        let mut p = SyslogParser::new(ctx_for("/var/log/syslog", jst()), false);
        p.ctx.hostname_hint = Some("hinted".to_string());
        assert!(matches_entry("Oct 26 17:39:01 sshd[1]: Accepted publickey"));
        let ev = one(&mut p, "Oct 26 17:39:01 sshd[1]: Accepted publickey");
        assert_eq!(
            ev.hostname.as_deref(),
            Some("hinted"),
            "no host on the line, so the hint is used"
        );
        assert_eq!(s(&ev, "process"), "sshd");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(1)));
        assert_eq!(s(&ev, "message"), "Accepted publickey");
        assert_eq!(ev.primary_logsource, "linux/sshd");
        let ev = one(&mut p, "Oct 26 17:39:01 kernel: [1.0] usb 1-1");
        assert_eq!(ev.hostname.as_deref(), Some("hinted"));
        assert_eq!(s(&ev, "process"), "kernel");
        assert_eq!(s(&ev, "message"), "[1.0] usb 1-1");
        // without a hint the hostname is simply absent
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "Oct 26 17:39:01 sshd[1]: Accepted publickey");
        assert_eq!(ev.hostname, None);
    }

    #[test]
    fn ipv6_host_ending_in_colons_is_a_host_not_a_process() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "Oct 26 17:39:01 fe80:: sshd[1]: msg");
        assert_eq!(ev.hostname.as_deref(), Some("fe80::"));
        assert_eq!(s(&ev, "process"), "sshd");
        let ev = one(&mut p, "Oct 26 17:39:01 2001:db8::1 sshd[1]: msg");
        assert_eq!(ev.hostname.as_deref(), Some("2001:db8::1"));
        assert_eq!(s(&ev, "process"), "sshd");
        assert_eq!(s(&ev, "message"), "msg");
        let ev = one(&mut p, "Oct 26 17:39:01 192.0.2.10 su[1]: msg");
        assert_eq!(ev.hostname.as_deref(), Some("192.0.2.10"));
        assert_eq!(ev.primary_logsource, "linux/auth");
    }

    #[test]
    fn message_without_a_process_has_null_process_and_pid() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "Oct 26 17:39:01 host -- MARK --");
        assert_eq!(ev.field("process"), Some(&FieldValue::Null));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
        assert_eq!(s(&ev, "message"), "-- MARK --");
        assert_eq!(ev.primary_logsource, "linux/syslog");
        assert_eq!(ev.tags, vec![SYSLOG]);
        assert_eq!(keys(&ev.fields[..3]), ["process", "pid", "message"]);
        let ev = one(&mut p, "Oct 26 17:39:01 host last message repeated 2 times");
        assert_eq!(ev.field("process"), Some(&FieldValue::Null));
        assert_eq!(s(&ev, "message"), "last message repeated 2 times");
    }

    #[test]
    fn empty_message_and_process_with_path_and_context() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "Oct 26 17:39:01 host proc[12]:");
        assert_eq!(s(&ev, "process"), "proc");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(12)));
        assert_eq!(s(&ev, "message"), "");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host /usr/sbin/cron[123]: (root) CMD (true)",
        );
        assert_eq!(s(&ev, "process"), "/usr/sbin/cron");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(123)));
        assert_eq!(ev.primary_logsource, "linux/cron");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host CRON(root)[456]: (root) CMD (true)",
        );
        assert_eq!(s(&ev, "process"), "CRON(root)");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(456)));
        assert_eq!(s(&ev, "message"), "(root) CMD (true)");
        assert_eq!(ev.tags, vec![SYSLOG, CRON]);
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host postfix/smtpd[15000]: connect from unknown",
        );
        assert_eq!(s(&ev, "process"), "postfix/smtpd");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(15000)));
        assert_eq!(s(&ev, "message"), "connect from unknown");
        assert_eq!(ev.tags, vec![SYSLOG]);
    }

    #[test]
    fn pri_prefix_gives_facility_and_severity_as_extra_fields() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(
            &mut p,
            "<34>Oct 26 17:39:01 host su[1]: (to root) user on pts/0",
        );
        assert_eq!(ts(&ev), "2026-10-26T17:39:01+09:00");
        assert_eq!(ev.hostname.as_deref(), Some("host"));
        assert_eq!(s(&ev, "process"), "su");
        assert_eq!(s(&ev, "message"), "(to root) user on pts/0");
        assert_eq!(
            keys(&ev.fields),
            ["process", "pid", "message", "facility", "severity"]
        );
        assert_eq!(ev.field("facility"), Some(&FieldValue::Int(4)));
        assert_eq!(ev.field("severity"), Some(&FieldValue::Int(2)));
        assert_eq!(ev.primary_logsource, "linux/auth");
        // RSYSLOG_ForwardFormat: PRI in front of an ISO timestamp
        let ev = one(
            &mut p,
            "<13>2026-10-26T17:39:01.123456+09:00 host proc[1]: m",
        );
        assert_eq!(ts(&ev), "2026-10-26T17:39:01.123456+09:00");
        assert!(ev.tz_explicit);
        assert_eq!(ev.field("facility"), Some(&FieldValue::Int(1)));
        assert_eq!(ev.field("severity"), Some(&FieldValue::Int(5)));
        // an out-of-range PRI is ignored but the line is still an entry
        let ev = one(&mut p, "<999>Oct 26 17:39:01 host proc: m");
        assert_eq!(s(&ev, "process"), "proc");
        assert_eq!(keys(&ev.fields), ["process", "pid", "message"]);
        assert!(!ev.timestamp_inferred);
    }

    #[test]
    fn leap_second_is_kept_and_invalid_clocks_are_continuations() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "Oct 26 17:39:60 host proc: leap");
        assert!(!ev.timestamp_inferred);
        assert_eq!(ts(&ev), "2026-10-26T17:39:60+09:00");
        assert_eq!(s(&ev, "process"), "proc");
        let ev = one(&mut p, "Oct 26 25:00:00 host proc: bad hour");
        assert!(
            ev.timestamp_inferred,
            "continuation borrows the previous time"
        );
        assert_eq!(ev.field("process"), None);
        assert_eq!(s(&ev, "message"), "Oct 26 25:00:00 host proc: bad hour");
    }

    #[test]
    fn impossible_date_keeps_the_entry_but_borrows_the_timestamp() {
        let mut p = syslog_parser("/var/log/syslog");
        let first = one(&mut p, "Oct 26 17:39:01 host proc: first");
        assert!(matches_entry("Feb 30 17:39:01 host proc: no such day"));
        let ev = one(&mut p, "Feb 30 17:39:01 host proc: no such day");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(s(&ev, "process"), "proc");
        assert_eq!(s(&ev, "message"), "no such day");
    }

    // ----------------------------------------------------------------------------------------
    // the other syslog fixtures
    // ----------------------------------------------------------------------------------------

    #[test]
    fn auth_log_fixture() {
        let events = parse_fixture("auth.log", false);
        assert_eq!(events.len(), 13);
        let primaries: Vec<&str> = events
            .iter()
            .map(|e| e.primary_logsource.as_str())
            .collect();
        assert_eq!(
            primaries,
            [
                "linux/sshd",
                "linux/sshd",
                "linux/sshd",
                "linux/sshd",
                "linux/sudo",
                "linux/sudo",
                "linux/auth",
                "linux/auth",
                "linux/cron",
                "linux/cron",
                "linux/auth",
                "linux/sshd",
                "linux/sshd",
            ]
        );
        for ev in &events {
            assert_eq!(ev.hostname.as_deref(), Some("webserver01"));
            assert!(ev.tags.contains(&SYSLOG));
            assert!(
                ev.tags.contains(&AUTH),
                "auth.log is file-tagged auth: {}",
                ev.raw
            );
            assert!(!ev.tz_explicit);
            assert!(!ev.timestamp_inferred);
        }
        // the file-derived tag comes before the process-derived ones
        assert_eq!(events[0].tags, vec![SYSLOG, AUTH, SSHD]);
        assert_eq!(events[4].tags, vec![SYSLOG, AUTH, SUDO]);
        assert_eq!(events[8].tags, vec![SYSLOG, AUTH, CRON]);
        assert_eq!(ts(&events[0]), "2026-10-26T18:00:01+09:00");
        assert_eq!(
            s(&events[0], "message"),
            "Invalid user admin from 198.51.100.23 port 40022"
        );
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(2001)));
        assert_eq!(s(&events[4], "process"), "sudo");
        assert_eq!(events[4].field("pid"), Some(&FieldValue::Null));
        assert!(s(&events[4], "message").starts_with("deploy : TTY=pts/1"));
        assert_eq!(s(&events[6], "process"), "su");
        assert_eq!(s(&events[6], "message"), "(to root) deploy on pts/1");
        assert_eq!(s(&events[8], "process"), "CRON");
        assert_eq!(s(&events[11], "process"), "sshd-session");
        assert_eq!(s(&events[11], "message"), "error in libcrypto");
        assert_eq!(s(&events[12], "process"), "sshd-auth");
        assert_eq!(
            s(&events[12], "message"),
            "Invalid user test from 198.51.100.24 port 40100"
        );
        assert_eq!(ts(&events[12]), "2026-10-26T18:05:01+09:00");
    }

    #[test]
    fn secure_fixture() {
        let events = parse_fixture("secure", false);
        assert_eq!(events.len(), 6);
        for ev in &events {
            assert_eq!(ev.hostname.as_deref(), Some("rhel9-web"));
            assert!(ev.tags.contains(&AUTH), "{}", ev.raw);
        }
        assert_eq!(ts(&events[0]), "2026-10-26T03:12:44+09:00");
        assert_eq!(
            s(&events[0], "message"),
            "error: PAM: Authentication failure for root from 192.0.2.44"
        );
        assert_eq!(events[0].primary_logsource, "linux/sshd");
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(31337)));
        // sudo[31400]:    ec2-user : ...  (pid and a padded user)
        assert_eq!(s(&events[3], "process"), "sudo");
        assert_eq!(events[3].field("pid"), Some(&FieldValue::Int(31400)));
        assert_eq!(
            s(&events[3], "message"),
            "ec2-user : TTY=pts/0 ; PWD=/home/ec2-user ; USER=root ; COMMAND=/bin/bash"
        );
        assert_eq!(events[3].primary_logsource, "linux/sudo");
        assert_eq!(s(&events[4], "process"), "unix_chkpwd");
        assert_eq!(events[4].primary_logsource, "linux/auth");
        assert_eq!(
            s(&events[4], "message"),
            "password check failed for user (root)"
        );
        assert_eq!(
            s(&events[5], "message"),
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.44  user=root"
        );
    }

    #[test]
    fn cron_fixture() {
        let events = parse_fixture("cron", false);
        assert_eq!(events.len(), 5);
        for ev in &events {
            assert_eq!(ev.primary_logsource, "linux/cron", "{}", ev.raw);
            assert_eq!(ev.tags, vec![SYSLOG, CRON], "{}", ev.raw);
            assert_eq!(ev.hostname.as_deref(), Some("rhel9-web"));
        }
        assert_eq!(ts(&events[0]), "2026-10-26T04:00:01+09:00");
        assert_eq!(s(&events[0], "process"), "CROND");
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(4000)));
        assert_eq!(
            s(&events[0], "message"),
            "(root) CMD (run-parts /etc/cron.hourly)"
        );
        // run-parts has no process tag of its own: the file tag makes it linux/cron
        assert_eq!(s(&events[1], "process"), "run-parts");
        assert_eq!(
            s(&events[1], "message"),
            "(/etc/cron.hourly) starting 0anacron"
        );
        assert_eq!(s(&events[2], "process"), "crontab");
        assert_eq!(s(&events[2], "message"), "(apache) REPLACE (apache)");
        assert_eq!(s(&events[4], "process"), "anacron");
        assert_eq!(s(&events[4], "message"), "Job `cron.daily' started");
        assert_eq!(ts(&events[4]), "2026-10-26T04:06:00+09:00");
    }

    #[test]
    fn rsyslog_iso_fixture_keeps_the_written_offset() {
        // the assumed zone is deliberately different from the one on the lines
        let path = fixture_path("rsyslog-iso.log");
        let mut p = SyslogParser::new(
            ctx_for(
                &path,
                TzAssumption::Fixed(FixedOffset::west_opt(5 * 3600).unwrap()),
            ),
            false,
        );
        let events: Vec<ParsedEvent> = fixture_lines("rsyslog-iso.log")
            .iter()
            .map(|l| one(&mut p, l))
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(ts(&events[0]), "2026-10-26T17:40:40.123456+09:00");
        assert_eq!(ts(&events[1]), "2026-10-26T17:44:05+09:00");
        assert_eq!(ts(&events[2]), "2026-10-26T17:46:00.500+09:00");
        for ev in &events {
            assert!(ev.tz_explicit);
            assert!(!ev.timestamp_inferred);
            assert_eq!(ev.hostname.as_deref(), Some("kali-linux-2025-2"));
            assert_eq!(ev.timestamp.unwrap().offset().local_minus_utc(), 9 * 3600);
            assert_eq!(keys(&ev.fields), ["process", "pid", "message"]);
        }
        assert_eq!(s(&events[0], "process"), "crontab");
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(12399)));
        assert_eq!(s(&events[0], "message"), "(user) REPLACE (user)");
        assert_eq!(events[0].primary_logsource, "linux/cron");
        assert_eq!(events[1].primary_logsource, "linux/sshd");
        assert_eq!(
            s(&events[1], "message"),
            "fatal: buffer_get_string: bad string"
        );
        assert_eq!(s(&events[2], "process"), "kernel");
        assert_eq!(events[2].field("pid"), Some(&FieldValue::Null));
        assert_eq!(
            s(&events[2], "message"),
            "[12345.678901] usb 1-1: new high-speed USB device number 5 using xhci_hcd"
        );
    }

    #[test]
    fn rfc5424_fixture() {
        let events = parse_fixture("rfc5424.log", false);
        assert_eq!(events.len(), 3);
        for ev in &events {
            assert!(ev.tz_explicit);
            assert!(!ev.timestamp_inferred);
            assert_eq!(ev.hostname.as_deref(), Some("webserver01"));
            assert_eq!(
                keys(&ev.fields),
                [
                    "process",
                    "pid",
                    "message",
                    "facility",
                    "severity",
                    "msgid",
                    "structured_data"
                ]
            );
            assert_eq!(ev.field("msgid"), Some(&FieldValue::Null));
            assert_eq!(ev.field("severity"), Some(&FieldValue::Int(6)));
            assert_eq!(
                ev.timestamp.unwrap().offset().local_minus_utc(),
                0,
                "Z is UTC"
            );
        }
        // <86>1 ... sshd 2003 - - Corrupted MAC on input.
        assert_eq!(ts(&events[0]), "2026-10-26T08:44:06+00:00");
        assert_eq!(s(&events[0], "process"), "sshd");
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(2003)));
        assert_eq!(s(&events[0], "message"), "Corrupted MAC on input.");
        assert_eq!(events[0].field("facility"), Some(&FieldValue::Int(10)));
        assert_eq!(events[0].field("structured_data"), Some(&FieldValue::Null));
        assert_eq!(events[0].tags, vec![SYSLOG, SSHD, AUTH]);
        assert_eq!(events[0].primary_logsource, "linux/sshd");
        // <78>1 ... crontab 12399 - [exampleSDID@32473 iut="3" eventSource="Application"] (user) REPLACE (user)
        assert_eq!(ts(&events[1]), "2026-10-26T08:40:40+00:00");
        assert_eq!(s(&events[1], "process"), "crontab");
        assert_eq!(events[1].field("pid"), Some(&FieldValue::Int(12399)));
        assert_eq!(s(&events[1], "message"), "(user) REPLACE (user)");
        assert_eq!(
            s(&events[1], "structured_data"),
            r#"[exampleSDID@32473 iut="3" eventSource="Application"]"#
        );
        assert_eq!(events[1].field("facility"), Some(&FieldValue::Int(9)));
        assert_eq!(events[1].primary_logsource, "linux/cron");
        assert_eq!(events[1].tags, vec![SYSLOG, CRON]);
        // <30>1 ... systemd 1 - - Started session-12.scope - Session 12 of User user.
        assert_eq!(ts(&events[2]), "2026-10-26T08:50:00+00:00");
        assert_eq!(s(&events[2], "process"), "systemd");
        assert_eq!(events[2].field("pid"), Some(&FieldValue::Int(1)));
        assert_eq!(events[2].field("facility"), Some(&FieldValue::Int(3)));
        assert_eq!(
            s(&events[2], "message"),
            "Started session-12.scope - Session 12 of User user."
        );
        assert_eq!(events[2].primary_logsource, "linux/syslog");
    }

    #[test]
    fn rfc5424_nil_values_bom_escapes_and_multiple_sd_elements() {
        let mut p = syslog_parser("/var/log/syslog");
        // every header field nil, no message
        let ev = one(&mut p, "<13>1 2026-10-26T17:39:01+09:00 - - - - -");
        assert_eq!(ts(&ev), "2026-10-26T17:39:01+09:00");
        assert_eq!(ev.hostname, None);
        assert_eq!(ev.field("process"), Some(&FieldValue::Null));
        assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
        assert_eq!(s(&ev, "message"), "");
        assert_eq!(ev.field("msgid"), Some(&FieldValue::Null));
        assert_eq!(ev.field("structured_data"), Some(&FieldValue::Null));
        assert_eq!(ev.primary_logsource, "linux/syslog");
        // BOM after the structured data, escaped quote and bracket inside a parameter value,
        // two SD elements, a non-numeric PROCID and a message ID
        let line = "<165>1 2026-10-26T17:39:01.000003-05:00 mymachine.example.com evntslog ID47 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App \\\"x\\] y\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] \u{FEFF}An application event log entry...";
        assert!(matches_entry(line));
        let ev = one(&mut p, line);
        assert_eq!(ts(&ev), "2026-10-26T17:39:01.000003-05:00");
        assert!(ev.tz_explicit);
        assert_eq!(ev.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(s(&ev, "process"), "evntslog");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Str("ID47".to_string())));
        assert_eq!(s(&ev, "msgid"), "ID47");
        assert_eq!(
            s(&ev, "structured_data"),
            "[exampleSDID@32473 iut=\"3\" eventSource=\"App \\\"x\\] y\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]"
        );
        assert_eq!(s(&ev, "message"), "An application event log entry...");
        assert_eq!(ev.field("facility"), Some(&FieldValue::Int(20)));
        assert_eq!(ev.field("severity"), Some(&FieldValue::Int(5)));
        // the message may start right after the BOM, or after one more space
        let ev = one(
            &mut p,
            "<13>1 2026-10-26T17:39:01Z host app 7 - -  two spaces",
        );
        assert_eq!(s(&ev, "message"), "two spaces");
        let ev = one(
            &mut p,
            "<13>1 2026-10-26T17:39:01Z host app 7 - - \u{FEFF} spaced",
        );
        assert_eq!(s(&ev, "message"), "spaced");
        // malformed structured data is not a 5424 entry (and not an ISO one either)
        assert!(!matches_entry(
            "<13>1 2026-10-26T17:39:01Z host app 7 - [broken msg"
        ));
    }

    #[test]
    fn rfc5424_nil_timestamp_borrows_the_previous_one() {
        let mut p = syslog_parser("/var/log/syslog");
        let first = one(&mut p, "<13>1 2026-10-26T17:39:01Z host app 7 - - first");
        let ev = one(&mut p, "<13>1 - host app 7 - - no time");
        assert_eq!(ev.timestamp, first.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(s(&ev, "process"), "app");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(7)));
        assert_eq!(s(&ev, "message"), "no time");
        // before any entry there is nothing to borrow
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "<13>1 - host app 7 - - no time");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
    }

    #[test]
    fn journalctl_short_iso_fixture() {
        let events = parse_fixture("journalctl-short-iso.log", false);
        assert_eq!(events.len(), 3);
        assert_eq!(ts(&events[0]), "2026-10-26T17:32:36+09:00");
        assert_eq!(ts(&events[1]), "2026-10-26T17:44:05+09:00");
        assert_eq!(ts(&events[2]), "2026-10-26T17:44:05.123456+09:00");
        for ev in &events {
            assert!(ev.tz_explicit, "+0900 is an explicit offset");
            assert!(!ev.timestamp_inferred);
            assert_eq!(ev.timestamp.unwrap().offset().local_minus_utc(), 9 * 3600);
            assert_eq!(ev.hostname.as_deref(), Some("kali-linux-2025-2"));
            assert_eq!(keys(&ev.fields), ["process", "pid", "message"]);
        }
        assert_eq!(s(&events[0], "process"), "systemd");
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(1)));
        assert_eq!(events[0].primary_logsource, "linux/syslog");
        assert_eq!(s(&events[1], "process"), "sshd");
        assert_eq!(events[1].field("pid"), Some(&FieldValue::Int(13002)));
        assert_eq!(events[1].primary_logsource, "linux/sshd");
        assert_eq!(
            s(&events[2], "message"),
            "Connection closed by 203.0.113.5 port 51234 [preauth]"
        );
        // negative offsets without a colon, and a journalctl boot marker as continuation
        let mut p = syslog_parser("journalctl");
        let ev = one(
            &mut p,
            "2026-10-26T03:32:36-0500 host kernel: Linux version 6.12",
        );
        assert_eq!(ts(&ev), "2026-10-26T03:32:36-05:00");
        assert_eq!(s(&ev, "process"), "kernel");
        let ev = one(&mut p, "-- Boot 0123456789abcdef0123456789abcdef --");
        assert!(ev.timestamp_inferred);
        assert_eq!(ts(&ev), "2026-10-26T03:32:36-05:00");
        assert_eq!(
            s(&ev, "message"),
            "-- Boot 0123456789abcdef0123456789abcdef --"
        );
    }

    #[test]
    fn iso_lines_need_a_zone_and_a_real_host() {
        // Without a zone an ISO-dated line is not syslog: dpkg, MySQL and PostgreSQL logs look
        // the same and would otherwise get words such as `install` as their host.
        for line in [
            "2026-10-26T17:39:01 host proc[1]: m",
            "2026-10-26 17:39:02 install netcat-traditional:amd64 <none> 1.10-48",
            "2026-10-26 17:39:01.123 JST [1234] LOG: database system is ready",
            "2026-10-26T08:44:06.123456Z 0 [System] [MY-010116] [Server] starting",
        ] {
            assert!(!matches_entry(line), "{line}");
        }
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(&mut p, "2026-10-26T08:39:01Z host proc[1]: m");
        assert_eq!(ts(&ev), "2026-10-26T08:39:01+00:00");
        assert!(ev.tz_explicit);
        assert_eq!(s(&ev, "process"), "proc");
    }

    #[test]
    fn sudoers_logfile_lines_have_no_host() {
        let mut p = syslog_parser("/var/log/sudo.log");
        let ev = one(
            &mut p,
            "Oct 26 17:46:00 : user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash",
        );
        assert_eq!(ev.hostname, None);
        assert!(s(&ev, "message").starts_with("user : TTY=pts/0"));
    }

    // ----------------------------------------------------------------------------------------
    // AppLog (amendment A5)
    // ----------------------------------------------------------------------------------------

    #[test]
    fn vsftpd_fixture() {
        let path = fixture_path("vsftpd.log");
        let mut p = SyslogParser::new(ctx_for(&path, jst()), true);
        p.ctx.hostname_hint = Some("ftp01".to_string());
        let events: Vec<ParsedEvent> = fixture_lines("vsftpd.log")
            .iter()
            .map(|l| one(&mut p, l))
            .collect();
        assert_eq!(events.len(), 4);
        for ev in &events {
            assert_eq!(ev.tags, vec![VSFTPD], "{}", ev.raw);
            assert_eq!(ev.primary_logsource, "linux/vsftpd");
            assert_eq!(
                ev.hostname.as_deref(),
                Some("ftp01"),
                "no host on the line → hint"
            );
            assert_eq!(s(ev, "process"), "vsftpd");
            assert!(!ev.tz_explicit);
            assert!(!ev.timestamp_inferred);
            assert_eq!(keys(&ev.fields), ["process", "pid", "user", "message"]);
        }
        // Sun Oct 26 17:39:01 2026 [pid 1234] CONNECT: Client "::ffff:203.0.113.40"
        assert_eq!(ts(&events[0]), "2026-10-26T17:39:01+09:00");
        assert_eq!(events[0].field("pid"), Some(&FieldValue::Int(1234)));
        assert_eq!(events[0].field("user"), Some(&FieldValue::Null));
        assert_eq!(
            s(&events[0], "message"),
            "CONNECT: Client \"::ffff:203.0.113.40\""
        );
        // Sun Oct 26 17:39:02 2026 [pid 1233] [ftpuser] FAIL LOGIN: Client "::ffff:203.0.113.40"
        assert_eq!(ts(&events[1]), "2026-10-26T17:39:02+09:00");
        assert_eq!(events[1].field("pid"), Some(&FieldValue::Int(1233)));
        assert_eq!(s(&events[1], "user"), "ftpuser");
        assert_eq!(
            s(&events[1], "message"),
            "FAIL LOGIN: Client \"::ffff:203.0.113.40\""
        );
        assert_eq!(
            s(&events[2], "message"),
            "OK LOGIN: Client \"::ffff:203.0.113.40\""
        );
        assert_eq!(ts(&events[3]), "2026-10-26T17:39:10+09:00");
        assert_eq!(events[3].field("pid"), Some(&FieldValue::Int(1235)));
        assert_eq!(
            s(&events[3], "message"),
            "OK DOWNLOAD: Client \"::ffff:203.0.113.40\", \"/pub/file.bin\", 1024 bytes, 10.00Kbyte/sec"
        );
        assert_eq!(events[3].raw, fixture_lines("vsftpd.log")[3]);
    }

    #[test]
    fn clamd_fixture() {
        let events = parse_fixture("clamav/clamd.log", true);
        assert_eq!(events.len(), 4);
        for ev in &events {
            assert_eq!(ev.tags, vec![CLAMAV], "{}", ev.raw);
            assert_eq!(ev.primary_logsource, "linux/clamav");
            assert_eq!(s(ev, "process"), "clamd");
            assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
            assert_eq!(ev.hostname, None, "no hint, no host");
            assert!(!ev.tz_explicit);
            assert_eq!(keys(&ev.fields[..3]), ["process", "pid", "message"]);
        }
        assert_eq!(ts(&events[0]), "2026-10-26T17:40:00+09:00");
        assert_eq!(
            s(&events[0], "message"),
            "+++ Started at Sun Oct 26 17:40:00 2026"
        );
        assert_eq!(s(&events[1], "message"), "Received POSIX_FADVISE");
        assert_eq!(ts(&events[2]), "2026-10-26T17:45:00+09:00");
        assert_eq!(
            s(&events[2], "message"),
            "/var/www/html/uploads/x.php: Php.Trojan.Webshell-1 FOUND"
        );
        assert_eq!(
            s(&events[3], "message"),
            "/var/www/html/uploads/y.php: Php.Malware.Agent-1234 FOUND"
        );
    }

    #[test]
    fn applog_timestamp_is_resolved_in_the_assumed_zone() {
        let line =
            "Sun Oct 26 17:45:00 2026 -> /var/www/html/uploads/x.php: Php.Trojan.Webshell-1 FOUND";
        let mut p = SyslogParser::new(
            ctx_for(
                "/var/log/clamav/clamd.log",
                TzAssumption::Fixed(FixedOffset::west_opt(5 * 3600).unwrap()),
            ),
            true,
        );
        let ev = one(&mut p, line);
        assert_eq!(ts(&ev), "2026-10-26T17:45:00-05:00");
        assert!(!ev.tz_explicit);
        assert_eq!(
            ev.timestamp.unwrap().naive_local().to_string(),
            "2026-10-26 17:45:00"
        );
        let mut p = SyslogParser::new(
            ctx_for(
                "/var/log/clamav/clamd.log",
                TzAssumption::Named(chrono_tz::Asia::Tokyo),
            ),
            true,
        );
        let ev = one(&mut p, line);
        assert_eq!(ts(&ev), "2026-10-26T17:45:00+09:00");
        assert_eq!(
            ev.timestamp.unwrap().to_utc().to_rfc3339(),
            "2026-10-26T08:45:00+00:00"
        );
    }

    #[test]
    fn freshclam_xferlog_and_unknown_applog_files() {
        // freshclam: `-> msg`, tagged clamav from the file name
        let mut p = applog_parser("/var/log/clamav/freshclam.log.1");
        let ev = one(
            &mut p,
            "Sun Oct 26 17:40:00 2026 -> daily.cld updated (version: 27000)",
        );
        assert_eq!(s(&ev, "process"), "freshclam");
        assert_eq!(ev.tags, vec![CLAMAV]);
        assert_eq!(s(&ev, "message"), "daily.cld updated (version: 27000)");
        // xferlog: no pid/user brackets, the whole rest is the message
        let mut p = applog_parser("/var/log/xferlog");
        let ev = one(
            &mut p,
            "Mon Oct 26 17:39:10 2026 1 203.0.113.40 1024 /pub/file.bin b _ o r ftpuser ftp 0 * c",
        );
        assert_eq!(s(&ev, "process"), "xferlog");
        assert_eq!(ev.tags, vec![VSFTPD]);
        assert_eq!(ev.primary_logsource, "linux/vsftpd");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Null));
        assert_eq!(ev.field("user"), None);
        assert_eq!(
            s(&ev, "message"),
            "1 203.0.113.40 1024 /pub/file.bin b _ o r ftpuser ftp 0 * c"
        );
        assert_eq!(ts(&ev), "2026-10-26T17:39:10+09:00");
        // rotated vsftpd file keeps the service name
        let mut p = applog_parser("/var/log/vsftpd.log.2.gz");
        let ev = one(
            &mut p,
            "Sun Oct 26 17:39:01 2026 [pid 1] CONNECT: Client \"1.2.3.4\"",
        );
        assert_eq!(s(&ev, "process"), "vsftpd");
        assert_eq!(ev.primary_logsource, "linux/vsftpd");
        // a file nobody hinted: linux/syslog and the rotation-free file name as the process
        let mut p = applog_parser("/opt/app/daemon.log.3");
        let ev = one(&mut p, "Sun Oct 26 17:39:01 2026 something happened");
        assert_eq!(ev.tags, vec![SYSLOG]);
        assert_eq!(ev.primary_logsource, "linux/syslog");
        assert_eq!(s(&ev, "process"), "daemon");
        assert_eq!(s(&ev, "message"), "something happened");
    }

    #[test]
    fn vsftpd_user_bracket_is_optional_and_may_be_empty() {
        let mut p = applog_parser("/var/log/vsftpd.log");
        let ev = one(
            &mut p,
            "Sun Oct 26 17:39:01 2026 [pid 1234] CONNECT: Client \"1.2.3.4\"",
        );
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(1234)));
        assert_eq!(ev.field("user"), Some(&FieldValue::Null));
        assert_eq!(s(&ev, "message"), "CONNECT: Client \"1.2.3.4\"");
        let ev = one(
            &mut p,
            "Sun Oct 26 17:39:01 2026 [pid 1234] [] FAIL LOGIN: Client \"1.2.3.4\"",
        );
        assert_eq!(ev.field("user"), Some(&FieldValue::Null));
        assert_eq!(s(&ev, "message"), "FAIL LOGIN: Client \"1.2.3.4\"");
        let ev = one(
            &mut p,
            "Sun Oct 26 17:39:01 2026 [pid 1234] [ftp user] OK LOGIN: Client \"1.2.3.4\"",
        );
        assert_eq!(s(&ev, "user"), "ftp user");
        assert_eq!(s(&ev, "message"), "OK LOGIN: Client \"1.2.3.4\"");
    }

    #[test]
    fn applog_continuations_and_strict_shapes() {
        // the AppLog parser treats syslog-shaped lines as continuations ...
        let mut p = applog_parser("/var/log/vsftpd.log");
        let first = one(
            &mut p,
            "Sun Oct 26 17:39:01 2026 [pid 1234] CONNECT: Client \"1.2.3.4\"",
        );
        let ev = one(&mut p, "Oct 26 17:39:02 host vsftpd[1234]: via syslog");
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.timestamp, first.timestamp);
        assert_eq!(ev.tags, vec![VSFTPD]);
        assert_eq!(ev.primary_logsource, "linux/vsftpd");
        assert_eq!(ev.field("process"), None);
        assert_eq!(
            s(&ev, "message"),
            "Oct 26 17:39:02 host vsftpd[1234]: via syslog"
        );
        // ... and the syslog parser treats AppLog-shaped lines as continuations
        let mut p = syslog_parser("/var/log/syslog");
        let first = one(&mut p, "Oct 26 17:39:01 host proc: first");
        let ev = one(
            &mut p,
            "Sun Oct 26 17:39:02 2026 [pid 1234] CONNECT: Client \"1.2.3.4\"",
        );
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.timestamp, first.timestamp);
        assert_eq!(ev.tags, vec![SYSLOG]);
        assert_eq!(ev.field("process"), None);
        // an AppLog continuation before any entry has no timestamp
        let mut p = applog_parser("/var/log/vsftpd.log");
        let ev = one(&mut p, "-> orphan");
        assert_eq!(ev.timestamp, None);
        assert!(!ev.timestamp_inferred);
        assert_eq!(s(&ev, "message"), "-> orphan");
    }

    // ----------------------------------------------------------------------------------------
    // year inference and zones (amendment A7)
    // ----------------------------------------------------------------------------------------

    #[test]
    fn december_lines_in_a_january_file_belong_to_the_previous_year() {
        let mut ctx = ctx_for("/var/log/syslog", jst());
        ctx.year_hint = 2027;
        ctx.mtime = Some(Utc.with_ymd_and_hms(2027, 1, 3, 12, 0, 0).unwrap());
        let mut p = SyslogParser::new(ctx, false);
        let ev = one(&mut p, "Dec 30 23:59:59 host proc: old year");
        assert_eq!(ts(&ev), "2026-12-30T23:59:59+09:00");
        let ev = one(&mut p, "Jan  1 00:00:01 host proc: new year");
        assert_eq!(ts(&ev), "2027-01-01T00:00:01+09:00");
        let ev = one(&mut p, "Jan  3 08:00:00 host proc: same day as the mtime");
        assert_eq!(ts(&ev), "2027-01-03T08:00:00+09:00");
        // one day after the mtime is still this year (clock skew tolerance)
        let ev = one(&mut p, "Jan  4 08:00:00 host proc: tomorrow");
        assert_eq!(ts(&ev), "2027-01-04T08:00:00+09:00");
        // further in the future than that: last year
        let ev = one(&mut p, "Jan  5 08:00:00 host proc: too far");
        assert_eq!(ts(&ev), "2026-01-05T08:00:00+09:00");
    }

    #[test]
    fn feb_29_falls_back_to_the_previous_leap_year() {
        let mut ctx = ctx_for("/var/log/syslog", jst());
        ctx.year_hint = 2029;
        ctx.mtime = Some(Utc.with_ymd_and_hms(2029, 1, 5, 0, 0, 0).unwrap());
        let mut p = SyslogParser::new(ctx, false);
        let ev = one(&mut p, "Feb 29 12:00:00 host proc: leap day");
        assert_eq!(ts(&ev), "2028-02-29T12:00:00+09:00");
        assert!(!ev.timestamp_inferred);
    }

    #[test]
    fn no_mtime_uses_the_year_hint_as_is() {
        let mut ctx = ctx_for("/var/log/syslog", jst());
        ctx.year_hint = 2024;
        ctx.mtime = None;
        let mut p = SyslogParser::new(ctx, false);
        let ev = one(&mut p, "Dec 31 23:59:59 host proc: m");
        assert_eq!(ts(&ev), "2024-12-31T23:59:59+09:00");
    }

    #[test]
    fn naive_times_resolve_with_the_tz_assumption() {
        let line = "Oct 26 17:39:01 host proc: m";
        let fixed = TzAssumption::Fixed(FixedOffset::west_opt(5 * 3600).unwrap());
        let mut p = SyslogParser::new(ctx_for("/var/log/syslog", fixed), false);
        let ev = one(&mut p, line);
        assert_eq!(ts(&ev), "2026-10-26T17:39:01-05:00");
        assert!(!ev.tz_explicit);
        assert_eq!(
            ev.timestamp.unwrap().to_utc().to_rfc3339(),
            "2026-10-26T22:39:01+00:00"
        );
        let utc = TzAssumption::Fixed(FixedOffset::east_opt(0).unwrap());
        let mut p = SyslogParser::new(ctx_for("/var/log/syslog", utc), false);
        assert_eq!(ts(&one(&mut p, line)), "2026-10-26T17:39:01+00:00");
        let tokyo = TzAssumption::Named(chrono_tz::Asia::Tokyo);
        let mut p = SyslogParser::new(ctx_for("/var/log/syslog", tokyo), false);
        assert_eq!(ts(&one(&mut p, line)), "2026-10-26T17:39:01+09:00");
        // a zone-carrying line ignores the assumption
        let mut p = SyslogParser::new(ctx_for("/var/log/syslog", fixed), false);
        let ev = one(&mut p, "2026-10-26T17:39:01+09:00 host proc: m");
        assert_eq!(ts(&ev), "2026-10-26T17:39:01+09:00");
        assert!(ev.tz_explicit);
    }

    // ----------------------------------------------------------------------------------------
    // continuations, blank lines, tags, fields
    // ----------------------------------------------------------------------------------------

    #[test]
    fn continuation_lines_borrow_the_timestamp_and_keep_the_file_tags() {
        let mut p = syslog_parser("/var/log/auth.log");
        let ev = one(&mut p, "sh: 1: wget: not found");
        assert_eq!(ev.timestamp, None, "nothing to borrow yet");
        assert!(!ev.timestamp_inferred);
        assert_eq!(ev.tags, vec![SYSLOG, AUTH]);
        assert_eq!(ev.primary_logsource, "linux/auth", "file-derived primary");
        assert_eq!(s(&ev, "message"), "sh: 1: wget: not found");
        assert_eq!(keys(&ev.fields[..1]), ["message"]);
        assert_eq!(ev.raw, "sh: 1: wget: not found");
        let entry = one(&mut p, "Oct 26 17:39:01 host sshd[1]: Accepted publickey");
        let ev = one(&mut p, "  thrown in /var/www/x.php on line 3");
        assert_eq!(ev.timestamp, entry.timestamp);
        assert!(ev.timestamp_inferred);
        assert_eq!(ev.hostname, None, "a continuation has no host of its own");
        assert_eq!(ev.tags, vec![SYSLOG, AUTH]);
        assert_eq!(s(&ev, "message"), "  thrown in /var/www/x.php on line 3");
        assert_eq!(ev.raw, "  thrown in /var/www/x.php on line 3");
        // a later entry moves the borrowed timestamp forward
        let later = one(&mut p, "Oct 26 17:40:00 host sshd[1]: next");
        let ev = one(&mut p, "#0 {main}");
        assert_eq!(ev.timestamp, later.timestamp);
        assert_ne!(ev.timestamp, entry.timestamp);
    }

    #[test]
    fn blank_lines_produce_no_event() {
        let mut p = syslog_parser("/var/log/syslog");
        assert!(p.parse_line("").is_none());
        assert!(p.parse_line("   ").is_none());
        assert!(p.parse_line("\t").is_none());
        let mut p = applog_parser("/var/log/vsftpd.log");
        assert!(p.parse_line("").is_none());
        assert!(p.parse_line(" \t ").is_none());
    }

    #[test]
    fn raw_is_the_whole_line_and_fields_are_ordered() {
        let mut p = syslog_parser("/var/log/syslog");
        let line = "<86>1 2026-10-26T08:44:06.000Z webserver01 sshd 2003 ID1 [a@1 b=\"c\"] Corrupted MAC on input.  ";
        let ev = one(&mut p, line);
        assert_eq!(ev.raw, line, "raw keeps trailing whitespace");
        assert_eq!(s(&ev, "message"), "Corrupted MAC on input.");
        assert_eq!(
            keys(&ev.fields),
            [
                "process",
                "pid",
                "message",
                "facility",
                "severity",
                "msgid",
                "structured_data"
            ]
        );
        assert_eq!(s(&ev, "msgid"), "ID1");
        let line = "Oct 26 17:39:01 host sshd[1]: trailing space ";
        let ev = one(&mut p, line);
        assert_eq!(ev.raw, line);
        assert_eq!(s(&ev, "message"), "trailing space");
        assert_eq!(keys(&ev.fields), ["process", "pid", "message"]);
    }

    #[test]
    fn context_extra_tags_and_hostname_hint() {
        let mut ctx = ctx_for("/srv/logs/custom.log", jst());
        ctx.extra_tags = vec![GUACAMOLE];
        ctx.hostname_hint = Some("hinted".to_string());
        let mut p = SyslogParser::new(ctx, false);
        // the line's own host wins over the hint; extra tags are appended
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 realhost guacd[9]: Connection closed",
        );
        assert_eq!(ev.hostname.as_deref(), Some("realhost"));
        assert_eq!(ev.tags, vec![SYSLOG, GUACAMOLE]);
        assert_eq!(ev.primary_logsource, "linux/guacamole");
        let ev = one(&mut p, "Oct 26 17:39:01 realhost proc[9]: m");
        assert_eq!(
            ev.tags,
            vec![SYSLOG, GUACAMOLE],
            "extra tag from the context"
        );
        assert_eq!(
            ev.primary_logsource, "linux/syslog",
            "extra tags do not set the primary"
        );
        // the nil host of RFC 5424 and continuations take the hint
        let ev = one(&mut p, "<13>1 2026-10-26T17:39:01Z - app 7 - - m");
        assert_eq!(ev.hostname.as_deref(), Some("hinted"));
        let ev = one(&mut p, "orphan line");
        assert_eq!(ev.hostname.as_deref(), Some("hinted"));
        assert_eq!(ev.tags, vec![SYSLOG, GUACAMOLE]);
    }

    #[test]
    fn file_hints_tag_every_line_and_process_tags_win_the_primary() {
        // cron file: run-parts has no process tag, the file tag is the primary
        let mut p = syslog_parser("/var/log/cron.log.1");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host run-parts[1]: starting 0anacron",
        );
        assert_eq!(ev.tags, vec![SYSLOG, CRON]);
        assert_eq!(ev.primary_logsource, "linux/cron");
        // ... but a process tag is more specific than the file tag
        let ev = one(&mut p, "Oct 26 17:39:01 host sshd[1]: m");
        assert_eq!(ev.tags, vec![SYSLOG, CRON, SSHD, AUTH]);
        assert_eq!(ev.primary_logsource, "linux/sshd");
        // duplicates are collapsed when file and process agree
        let mut p = syslog_parser("/var/log/secure-20261026");
        let ev = one(&mut p, "Oct 26 17:39:01 host su[1]: m");
        assert_eq!(ev.tags, vec![SYSLOG, AUTH]);
        assert_eq!(ev.primary_logsource, "linux/auth");
        let ev = one(&mut p, "Oct 26 17:39:01 host sudo[1]: m");
        assert_eq!(ev.tags, vec![SYSLOG, AUTH, SUDO]);
        assert_eq!(ev.primary_logsource, "linux/sudo");
        // a plain syslog file without hints
        let mut p = syslog_parser("/var/log/messages");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host clamd[1]: SelfCheck: Database status OK.",
        );
        assert_eq!(ev.tags, vec![SYSLOG, CLAMAV]);
        assert_eq!(ev.primary_logsource, "linux/clamav");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host vsftpd[1]: CONNECT: Client \"1.2.3.4\"",
        );
        assert_eq!(ev.primary_logsource, "linux/vsftpd");
        let ev = one(
            &mut p,
            "Oct 26 17:39:01 host php-fpm8.3[1]: PHP Warning:  x",
        );
        assert_eq!(ev.tags, vec![SYSLOG, LogSourceTag::PHP_FPM, PHP]);
        assert_eq!(ev.primary_logsource, "php/fpm");
    }

    #[test]
    fn php_process_gets_the_php_error_log_tag_from_its_name() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(
            &mut p,
            "Oct 26 17:53:00 host php[14100]: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
        );
        assert!(ev.tags.contains(&PHP));
        assert_eq!(ev.primary_logsource, "php/error_log");
        assert_eq!(s(&ev, "process"), "php");
        assert_eq!(ev.field("pid"), Some(&FieldValue::Int(14100)));
        assert!(s(&ev, "message").starts_with("PHP Fatal error:  Allowed memory size"));
        assert_eq!(ts(&ev), "2026-10-26T17:53:00+09:00");
    }

    #[test]
    fn events_match_sigma_rules_through_logsource_and_fields() {
        let mut p = syslog_parser("/var/log/syslog");
        let ev = one(
            &mut p,
            "Oct 26 17:52:00 kali sshd-session[13100]: error: Corrupted MAC on input.",
        );
        let rule = sigma_rust::rule_from_yaml(
            "title: t\nlogsource: {product: linux, service: sshd}\ndetection:\n  sel:\n    message|contains: 'Corrupted MAC'\n    pid: 13100\n    hostname: kali\n  condition: sel\n",
        )
        .unwrap();
        assert!(LogSourceSpec::from_rule(&rule).matches_any(&ev.tags));
        assert!(rule.is_match(&ev.to_sigma_event()));
        // the auth tag is on the same event, the cron tag is not
        assert!(LogSourceSpec::new(Some("linux"), None, Some("auth")).matches_any(&ev.tags));
        assert!(LogSourceSpec::new(Some("linux"), None, None).matches_any(&ev.tags));
        assert!(!LogSourceSpec::new(Some("linux"), None, Some("cron")).matches_any(&ev.tags));
        // `raw` carries the whole line, header included (rules.rs rewrites keyword lists to
        // `raw|contains`, amendment A11)
        let kw = sigma_rust::rule_from_yaml(
            "title: k\nlogsource: {product: linux}\ndetection:\n  sel:\n    raw|startswith: 'Oct 26 17:52:00 kali sshd-session'\n  condition: sel\n",
        )
        .unwrap();
        assert!(kw.is_match(&ev.to_sigma_event()));
        // a Null pid is a `null` test hit
        let ev = one(&mut p, "Oct 26 17:45:00 kali sudo:     user : TTY=pts/0");
        let null_rule = sigma_rust::rule_from_yaml(
            "title: n\nlogsource: {product: linux, service: sudo}\ndetection:\n  sel:\n    pid: null\n    process: sudo\n  condition: sel\n",
        )
        .unwrap();
        assert!(LogSourceSpec::from_rule(&null_rule).matches_any(&ev.tags));
        assert!(null_rule.is_match(&ev.to_sigma_event()));
    }

    #[test]
    fn parser_for_dispatches_both_formats() {
        let mut p = parser_for(&LogFormat::Syslog.into(), ctx_for("/var/log/syslog", jst()));
        let ev = p
            .parse_line("Oct 26 17:39:01 host sshd[1]: m")
            .expect("entry");
        assert_eq!(ev.primary_logsource, "linux/sshd");
        assert_eq!(ts(&ev), "2026-10-26T17:39:01+09:00");
        let mut p = parser_for(
            &LogFormat::AppLog.into(),
            ctx_for("/var/log/vsftpd.log", jst()),
        );
        let ev = p
            .parse_line("Sun Oct 26 17:39:01 2026 [pid 1] [u] OK LOGIN: Client \"1.2.3.4\"")
            .expect("entry");
        assert_eq!(ev.primary_logsource, "linux/vsftpd");
        assert_eq!(s(&ev, "user"), "u");
        assert!(p.parse_line("").is_none());
    }
}
