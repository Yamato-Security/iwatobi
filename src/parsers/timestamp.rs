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

//! Timestamp helpers shared by every parser.
//!
//! Policy (design §4 and amendment A7):
//! - A timestamp that carries its own zone is used as-is.
//! - A naive timestamp is interpreted in the [`TzAssumption`] (`-z`, default local): DST gaps move
//!   forward one hour, ambiguous times take the earliest instant.
//! - Syslog lines without a year get the year of the file's mtime, minus one when that would place
//!   the line more than a day after the mtime (a log that crossed New Year), retrying `year - 1`
//!   when the date does not exist in that year (Feb 29).

use chrono::{
    DateTime, Datelike, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, Offset, TimeZone, Utc,
};
use chrono_tz::Tz;
use std::str::FromStr;

/// Which zone to assume for timestamps that carry none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TzAssumption {
    #[default]
    Local,
    Fixed(FixedOffset),
    Named(Tz),
}

impl FromStr for TzAssumption {
    type Err = String;

    /// Accepts `local`, `UTC`/`Z`, `+09:00`/`+0900`/`-05:00` and IANA names such as `Asia/Tokyo`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("local") {
            return Ok(TzAssumption::Local);
        }
        if let Some(off) = parse_fixed_offset(t) {
            return Ok(TzAssumption::Fixed(off));
        }
        if let Ok(tz) = t.parse::<Tz>() {
            return Ok(TzAssumption::Named(tz));
        }
        Err(format!(
            "'{s}' is not a timezone (use an IANA name such as Asia/Tokyo, UTC, or an offset such as +09:00)"
        ))
    }
}

impl std::fmt::Display for TzAssumption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TzAssumption::Local => write!(f, "local"),
            TzAssumption::Fixed(off) => write!(f, "{off}"),
            TzAssumption::Named(tz) => write!(f, "{}", tz.name()),
        }
    }
}

/// How a naive local time was resolved; `Ambiguous`/`Gap` are reported once per file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Exact,
    Ambiguous,
    Gap,
}

fn pick<T: TimeZone>(
    result: LocalResult<DateTime<T>>,
    naive: NaiveDateTime,
    tz: &T,
) -> (DateTime<T>, Resolution) {
    match result {
        LocalResult::Single(dt) => (dt, Resolution::Exact),
        LocalResult::Ambiguous(earliest, _) => (earliest, Resolution::Ambiguous),
        LocalResult::None => {
            let shifted = naive + chrono::Duration::hours(1);
            match tz.from_local_datetime(&shifted) {
                LocalResult::Single(dt) => (dt, Resolution::Gap),
                LocalResult::Ambiguous(e, _) => (e, Resolution::Gap),
                LocalResult::None => (tz.from_utc_datetime(&naive), Resolution::Gap),
            }
        }
    }
}

/// Interpret a naive timestamp in the assumed zone.
pub fn resolve_naive(
    naive: NaiveDateTime,
    tz: &TzAssumption,
) -> (DateTime<FixedOffset>, Resolution) {
    match tz {
        TzAssumption::Fixed(off) => (off.from_utc_datetime(&(naive - *off)), Resolution::Exact),
        TzAssumption::Local => {
            let local = chrono::Local;
            let (dt, res) = pick(local.from_local_datetime(&naive), naive, &local);
            (dt.fixed_offset(), res)
        }
        TzAssumption::Named(z) => {
            let (dt, res) = pick(z.from_local_datetime(&naive), naive, z);
            let off = dt.offset().fix();
            (off.from_utc_datetime(&dt.naive_utc()), res)
        }
    }
}

/// `Jan`..`Dec` (case-insensitive) → 1..12.
pub fn month_from_abbr(s: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let l = s.to_ascii_lowercase();
    MONTHS.iter().position(|m| *m == l).map(|i| i as u32 + 1)
}

/// Year for a month/day that was logged without a year (RFC 3164).
///
/// `mtime_date` is the file's modification date in the zone the log was written in: a log
/// rotated at 06:25 JST on 1 January was modified on 31 December in UTC.
pub fn infer_year(month: u32, day: u32, year_hint: i32, mtime_date: Option<NaiveDate>) -> i32 {
    let valid = |y: i32| NaiveDate::from_ymd_opt(y, month, day).is_some();
    let mut year = year_hint;
    if !valid(year) {
        year -= 1;
        if !valid(year) {
            return year_hint;
        }
    }
    if let Some(mtime_date) = mtime_date
        && let Some(date) = NaiveDate::from_ymd_opt(year, month, day)
    {
        let limit = mtime_date + chrono::Duration::days(1);
        if date > limit {
            let prev = year - 1;
            if valid(prev) {
                return prev;
            }
        }
    }
    year
}

/// `+09:00`, `+0900`, `-05:00`, `Z`/`UTC`/`GMT` → offset.
pub fn parse_fixed_offset(s: &str) -> Option<FixedOffset> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("z") || t.eq_ignore_ascii_case("utc") || t.eq_ignore_ascii_case("gmt")
    {
        return FixedOffset::east_opt(0);
    }
    let (sign, rest) = match t.chars().next()? {
        '+' => (1, &t[1..]),
        '-' => (-1, &t[1..]),
        _ => return None,
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if !(digits.len() == 4 || digits.len() == 2) || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (h, m) = if digits.len() == 4 {
        (
            digits[..2].parse::<i32>().ok()?,
            digits[2..].parse::<i32>().ok()?,
        )
    } else {
        (digits.parse::<i32>().ok()?, 0)
    };
    if h > 23 || m > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

/// A zone token as written in a PHP error log (`UTC`, `Europe/Berlin`, `+09:00`).
pub fn parse_zone_token(s: &str) -> Option<TzAssumption> {
    if let Some(off) = parse_fixed_offset(s) {
        return Some(TzAssumption::Fixed(off));
    }
    s.parse::<Tz>().ok().map(TzAssumption::Named)
}

/// RFC 3339 / ISO 8601-like timestamps, tolerant of a space instead of `T`, fractional seconds,
/// and offsets without a colon (`+0900`, as journalctl `short-iso` writes). Returns `None` when
/// the text has no zone (the caller resolves it with [`resolve_naive`]) or does not parse.
pub fn parse_iso_with_zone(s: &str) -> Option<DateTime<FixedOffset>> {
    let t = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt);
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%.f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%d %H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%d %H:%M:%S%.fZ",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(t, fmt) {
            return Some(dt);
        }
    }
    // `...Z` with the Z handled as a literal above only for fractional forms; plain `Z`:
    if let Some(stripped) = t.strip_suffix('Z')
        && let Some(naive) = parse_iso_naive(stripped)
    {
        return Some(Utc.from_utc_datetime(&naive).fixed_offset());
    }
    None
}

/// ISO-like timestamp without a zone (`2026-10-26T17:39:01.123`, `2026-10-26 17:39:01`).
pub fn parse_iso_naive(s: &str) -> Option<NaiveDateTime> {
    let t = s.trim();
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(t, fmt) {
            return Some(dt);
        }
    }
    None
}

/// Apache/nginx CLF time `26/Oct/2026:17:39:01 +0900` (with or without the brackets).
pub fn parse_clf_time(s: &str) -> Option<DateTime<FixedOffset>> {
    let t = s.trim().trim_start_matches('[').trim_end_matches(']');
    DateTime::parse_from_str(t, "%d/%b/%Y:%H:%M:%S %z").ok()
}

/// Epoch timestamps: `< 1e11` seconds (fractional allowed), `< 1e14` milliseconds, else microseconds.
pub fn parse_epoch(value: f64) -> Option<DateTime<Utc>> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let (secs, nanos) = if value < 1e11 {
        // f64 carries ~16 significant digits: with 10 digits of seconds the fraction is only
        // good to microseconds, so round there instead of amplifying the noise into nanoseconds.
        let secs = value.trunc();
        let micros = ((value - secs) * 1e6).round() as u32;
        (secs as i64, micros.min(999_999) * 1000)
    } else if value < 1e14 {
        let ms = value as i64;
        (
            ms.div_euclid(1000),
            (ms.rem_euclid(1000) * 1_000_000) as u32,
        )
    } else {
        let us = value as i64;
        (
            us.div_euclid(1_000_000),
            (us.rem_euclid(1_000_000) * 1000) as u32,
        )
    };
    DateTime::from_timestamp(secs, nanos.min(999_999_999))
}

/// Build a naive date-time from parts, `None` when they do not form a valid date.
pub fn naive_from_parts(
    year: i32,
    month: u32,
    day: u32,
    h: u32,
    m: u32,
    s: u32,
    nanos: u32,
) -> Option<NaiveDateTime> {
    NaiveDate::from_ymd_opt(year, month, day)?.and_hms_nano_opt(h, m, s, nanos)
}

/// Parse a fractional-seconds suffix such as `.123456` into nanoseconds.
pub fn frac_to_nanos(frac: &str) -> u32 {
    let digits: String = frac.trim_start_matches('.').chars().take(9).collect();
    if digits.is_empty() {
        return 0;
    }
    let padded = format!("{digits:0<9}");
    padded.parse().unwrap_or(0)
}

/// The year a file was last modified, for syslog year inference.
pub fn year_of(mtime: Option<DateTime<Utc>>, tz: &TzAssumption) -> i32 {
    local_date(mtime.unwrap_or_else(Utc::now), tz).year()
}

/// The calendar date of an instant in the assumed zone.
pub fn local_date(t: DateTime<Utc>, tz: &TzAssumption) -> NaiveDate {
    match tz {
        TzAssumption::Local => t.with_timezone(&chrono::Local).date_naive(),
        TzAssumption::Fixed(off) => t.with_timezone(off).date_naive(),
        TzAssumption::Named(z) => t.with_timezone(z).date_naive(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tz_assumption_parsing() {
        assert_eq!(
            "local".parse::<TzAssumption>().unwrap(),
            TzAssumption::Local
        );
        assert_eq!(
            "UTC".parse::<TzAssumption>().unwrap(),
            TzAssumption::Fixed(FixedOffset::east_opt(0).unwrap())
        );
        assert_eq!(
            "+09:00".parse::<TzAssumption>().unwrap(),
            TzAssumption::Fixed(FixedOffset::east_opt(9 * 3600).unwrap())
        );
        assert_eq!(
            "-0500".parse::<TzAssumption>().unwrap(),
            TzAssumption::Fixed(FixedOffset::west_opt(5 * 3600).unwrap())
        );
        assert_eq!(
            "Asia/Tokyo".parse::<TzAssumption>().unwrap(),
            TzAssumption::Named(chrono_tz::Asia::Tokyo)
        );
        assert!("Mars/Olympus".parse::<TzAssumption>().is_err());
    }

    #[test]
    fn naive_resolution_handles_dst() {
        let berlin = TzAssumption::Named(chrono_tz::Europe::Berlin);
        // 2026-03-29 02:30 does not exist in Berlin (spring forward) -> 03:30 CEST
        let gap = NaiveDate::from_ymd_opt(2026, 3, 29)
            .unwrap()
            .and_hms_opt(2, 30, 0)
            .unwrap();
        let (dt, res) = resolve_naive(gap, &berlin);
        assert_eq!(res, Resolution::Gap);
        assert_eq!(dt.to_rfc3339(), "2026-03-29T03:30:00+02:00");
        // 2026-10-25 02:30 happens twice -> earliest (CEST)
        let amb = NaiveDate::from_ymd_opt(2026, 10, 25)
            .unwrap()
            .and_hms_opt(2, 30, 0)
            .unwrap();
        let (dt, res) = resolve_naive(amb, &berlin);
        assert_eq!(res, Resolution::Ambiguous);
        assert_eq!(dt.to_rfc3339(), "2026-10-25T02:30:00+02:00");
        let fixed = TzAssumption::Fixed(FixedOffset::east_opt(9 * 3600).unwrap());
        let (dt, res) = resolve_naive(
            NaiveDate::from_ymd_opt(2026, 10, 26)
                .unwrap()
                .and_hms_opt(17, 39, 1)
                .unwrap(),
            &fixed,
        );
        assert_eq!(res, Resolution::Exact);
        assert_eq!(dt.to_rfc3339(), "2026-10-26T17:39:01+09:00");
    }

    #[test]
    fn year_inference() {
        let mtime = Utc.with_ymd_and_hms(2027, 1, 3, 0, 0, 0).unwrap();
        assert_eq!(
            infer_year(12, 30, 2027, Some(mtime.date_naive())),
            2026,
            "Dec line in a file modified in Jan"
        );
        assert_eq!(infer_year(1, 2, 2027, Some(mtime.date_naive())), 2027);
        assert_eq!(
            infer_year(
                2,
                29,
                2029,
                Some(
                    Utc.with_ymd_and_hms(2029, 1, 5, 0, 0, 0)
                        .unwrap()
                        .date_naive()
                )
            ),
            2028,
            "Feb 29 only valid in 2028"
        );
        assert_eq!(infer_year(10, 26, 2026, None), 2026);
    }

    #[test]
    fn iso_variants() {
        assert_eq!(
            parse_iso_with_zone("2026-10-26T17:32:36+0900")
                .unwrap()
                .to_rfc3339(),
            "2026-10-26T17:32:36+09:00"
        );
        assert_eq!(
            parse_iso_with_zone("2026-10-26T17:32:36.123456+0900")
                .unwrap()
                .to_rfc3339(),
            "2026-10-26T17:32:36.123456+09:00"
        );
        assert_eq!(
            parse_iso_with_zone("2026-10-26T17:39:01.123456+09:00")
                .unwrap()
                .to_rfc3339(),
            "2026-10-26T17:39:01.123456+09:00"
        );
        assert_eq!(
            parse_iso_with_zone("2026-10-24T15:35:32.869295Z")
                .unwrap()
                .to_rfc3339(),
            "2026-10-24T15:35:32.869295+00:00"
        );
        assert_eq!(
            parse_iso_with_zone("2026-10-24T15:35:32Z")
                .unwrap()
                .to_rfc3339(),
            "2026-10-24T15:35:32+00:00"
        );
        assert!(parse_iso_with_zone("2026-10-24T15:35:32").is_none());
        assert!(parse_iso_naive("2026-10-24 15:35:32").is_some());
    }

    #[test]
    fn clf_and_epoch() {
        assert_eq!(
            parse_clf_time("[26/Oct/2026:17:39:01 +0900]")
                .unwrap()
                .to_rfc3339(),
            "2026-10-26T17:39:01+09:00"
        );
        assert_eq!(
            parse_epoch(1792856132.869)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2026-10-24T15:35:32.869Z"
        );
        assert_eq!(
            parse_epoch(1792856132869.0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2026-10-24T15:35:32.869Z"
        );
        assert_eq!(
            parse_epoch(1792856132869295.0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "2026-10-24T15:35:32.869295Z"
        );
        assert_eq!(frac_to_nanos(".123"), 123_000_000);
        assert_eq!(frac_to_nanos(".123456789"), 123_456_789);
        assert_eq!(month_from_abbr("Oct"), Some(10));
        assert!(matches!(
            parse_zone_token("Europe/Berlin"),
            Some(TzAssumption::Named(_))
        ));
        assert!(matches!(
            parse_zone_token("+09:00"),
            Some(TzAssumption::Fixed(_))
        ));
        assert!(parse_zone_token("JST").is_none());
    }
}
