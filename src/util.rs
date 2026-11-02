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

//! Small shared helpers: colored printing, fatal errors, output sanitizing and embedded assets.

use crate::color::IwatobiColor;
use crate::errorlog::log_error;
use std::io::Write;
use std::path::{Path, PathBuf};
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

/// Print `msg` to stdout in `color` (or the default color when `None`).
pub fn p(color: Option<Color>, msg: &str, newline: bool) {
    // Only emit escape sequences when there is a color to set: `set_color` with an empty spec
    // would still write a reset sequence, which must not happen with `-K, --no-color`.
    let wtr = BufferWriter::stdout(if color.is_some() {
        ColorChoice::Always
    } else {
        ColorChoice::Never
    });
    let mut buf = wtr.buffer();
    if let Some(c) = color {
        buf.set_color(ColorSpec::new().set_fg(Some(c))).ok();
    }
    if newline {
        writeln!(buf, "{msg}").ok();
    } else {
        write!(buf, "{msg}").ok();
    }
    if color.is_some() {
        buf.reset().ok();
    }
    wtr.print(&buf).ok();
}

/// Print a `Label: value` pair with a green label, like the sibling tools.
pub fn p_label(no_color: bool, label: &str, value: &str) {
    p(IwatobiColor::Green.rdg(no_color), label, false);
    p(None, value, true);
}

/// Prints a run-ending error in red.
pub fn error_msg(no_color: bool, msg: &str) {
    p(IwatobiColor::Red.rdg(no_color), msg, true);
}

/// Prints a warning in orange (also recorded in the error log by the caller when it matters).
pub fn warn_msg(no_color: bool, msg: &str) {
    p(IwatobiColor::Orange.rdg(no_color), msg, true);
}

/// Prints a fatal error in red, records it, and exits with a non-zero status.
pub fn fatal_error(no_color: bool, msg: &str) -> ! {
    log_error(msg);
    error_msg(no_color, msg);
    std::process::exit(1);
}

/// Neutralizes CSV/spreadsheet formula injection (CWE-1236) for a single field: a cell starting
/// with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with an apostrophe. CSV only.
pub fn sanitize_csv_field(field: &str) -> String {
    // A cell that is only the `-` placeholder is plain text to every spreadsheet; keep it readable.
    if field == "-" {
        return field.to_string();
    }
    if field
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
    {
        let mut s = String::with_capacity(field.len() + 1);
        s.push('\'');
        s.push_str(field);
        s
    } else {
        field.to_string()
    }
}

/// Replaces C0/C1 control characters other than tab with a visible `\xHH` escape so that
/// attacker-controlled log text (PHP warnings, shell stderr, request paths) cannot inject
/// terminal escape sequences or hidden characters into the terminal, CSV or JSON output.
pub fn sanitize_control_chars(value: &str) -> String {
    if !value.chars().any(is_unsafe_control) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if is_unsafe_control(c) {
            out.push_str(&format!("\\x{:02X}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn is_unsafe_control(c: char) -> bool {
    c != '\t' && (c.is_control() || ('\u{80}'..='\u{9f}').contains(&c))
}

/// Name of an embedded asset that may be overridden by a file in `./config/` or `./art/` next to
/// the executable or in the current directory.
pub fn asset(relative: &str, embedded: &'static str) -> String {
    for base in override_dirs() {
        let candidate = base.join(relative);
        if candidate.is_file()
            && let Ok(text) = std::fs::read_to_string(&candidate)
        {
            return text;
        }
    }
    embedded.to_string()
}

fn override_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        dirs.push(dir.to_path_buf());
    }
    dirs
}

/// Resolve the default `./rules` directory: the current directory first, then next to the
/// executable (so `iwatobi` works when started from another directory), like Hayabusa.
pub fn resolve_default_dir(name: &str) -> PathBuf {
    let direct = PathBuf::from(name);
    if direct.exists() {
        return direct;
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    direct
}

/// The local machine's host name, used as `Computer` for events that carry none in live analysis.
pub fn local_hostname() -> Option<String> {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.is_empty())
}

/// Human readable file size for the "Results saved" line.
pub fn file_size_display(path: &Path) -> String {
    match path.metadata() {
        Ok(m) => bytesize::ByteSize::b(m.len()).display().to_string(),
        Err(_) => "-".to_string(),
    }
}

/// `n` with thousands separators.
pub fn fmt_num(n: usize) -> String {
    use num_format::{Locale, ToFormattedString};
    n.to_formatted_string(&Locale::en)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_formula_prefixes_are_neutralized() {
        assert_eq!(sanitize_csv_field("=1+1"), "'=1+1");
        assert_eq!(sanitize_csv_field("-"), "-");
        assert_eq!(sanitize_csv_field("-1+1"), "'-1+1");
        assert_eq!(sanitize_csv_field("@cmd"), "'@cmd");
        assert_eq!(sanitize_csv_field("plain"), "plain");
    }

    #[test]
    fn control_characters_become_visible_escapes() {
        assert_eq!(
            sanitize_control_chars("a\u{1b}]0;pwned\u{7}b"),
            "a\\x1B]0;pwned\\x07b"
        );
        assert_eq!(sanitize_control_chars("tab\tkept"), "tab\tkept");
        assert_eq!(sanitize_control_chars("c1\u{9b}x"), "c1\\x9Bx");
        assert_eq!(sanitize_control_chars("日本語"), "日本語");
    }
}
