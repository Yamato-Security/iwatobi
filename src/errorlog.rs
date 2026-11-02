// Copyright (C) 2026 Shirofune Security Co., Ltd.
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

//! Error/warning log file.
//!
//! Warnings and errors raised while processing logs are written to
//! `logs/errorlog-<YYYYMMDD_HHMMSS>.log` instead of the terminal, exactly like Hayabusa and
//! Suzaku: a directory full of unreadable files would otherwise bury the results, and the run
//! prints a single pointer to the file at the end. The file is created lazily on the first
//! message, so a clean run leaves no `logs/` directory behind. Its first line is the command line
//! that produced it. `-Q, --quiet-errors` disables the file; messages are then dropped.

use chrono::Local;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

const LOG_DIR: &str = "logs";

static QUIET: AtomicBool = AtomicBool::new(false);
/// Set when the log file could not be created, so the failure is reported once and later
/// messages go straight to stderr instead of retrying (and repeating the failure) every time.
static UNAVAILABLE: AtomicBool = AtomicBool::new(false);

struct ErrorLog {
    path: PathBuf,
    writer: BufWriter<File>,
    count: usize,
}

fn state() -> &'static Mutex<Option<ErrorLog>> {
    static STATE: OnceLock<Mutex<Option<ErrorLog>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// Disable the error log (`-Q, --quiet-errors`).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Records a non-fatal warning. Not shown on the terminal.
pub fn log_warn(msg: &str) {
    write_entry("WARNING", msg);
}

/// Records an error. Not shown on the terminal, except by the call sites that also print it.
pub fn log_error(msg: &str) {
    write_entry("ERROR", msg);
}

/// Path of the log file, once one has been created.
pub fn log_path() -> Option<PathBuf> {
    state()
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|log| log.path.clone()))
}

/// Number of messages recorded so far.
pub fn entry_count() -> usize {
    state()
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|log| log.count))
        .unwrap_or(0)
}

fn write_entry(level: &str, msg: &str) {
    if QUIET.load(Ordering::Relaxed) {
        return;
    }
    let line = format!("[{level}] {msg}");
    if UNAVAILABLE.load(Ordering::Relaxed) {
        eprintln!("{line}");
        return;
    }
    let Ok(mut guard) = state().lock() else {
        eprintln!("{line}");
        return;
    };
    if guard.is_none() {
        match create_log(Path::new(LOG_DIR), &command_line()) {
            Ok(log) => *guard = Some(log),
            Err(e) => {
                UNAVAILABLE.store(true, Ordering::Relaxed);
                eprintln!("Cannot write to the error log in ./{LOG_DIR}: {e}");
                eprintln!("{line}");
                return;
            }
        }
    }
    let Some(log) = guard.as_mut() else { return };
    if writeln!(log.writer, "{line}")
        .and_then(|_| log.writer.flush())
        .is_err()
    {
        eprintln!("{line}");
        return;
    }
    log.count += 1;
}

fn command_line() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

fn create_log(dir: &Path, command_line: &str) -> std::io::Result<ErrorLog> {
    fs::create_dir_all(dir)?;
    // `create_new` so two runs started in the same second never share (and truncate) one file.
    let stamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let mut attempt = 0u32;
    let (path, file) = loop {
        let name = if attempt == 0 {
            format!("errorlog-{stamp}.log")
        } else {
            format!("errorlog-{stamp}-{attempt}.log")
        };
        let path = dir.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => break (path, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 1000 => {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    };
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{command_line}")?;
    writer.flush()?;
    Ok(ErrorLog {
        path,
        writer,
        count: 0,
    })
}
