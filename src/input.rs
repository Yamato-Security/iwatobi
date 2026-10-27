//! Input enumeration and line reading (design §5).
//!
//! `-d` recurses; regular files only; `.gz` is decoded transparently; `.xz/.bz2/.zst`, binary
//! files (NUL in the sample), `wtmp`/`btmp`/`lastlog`, journal files and empty files are skipped
//! with a warning in the error log.

use crate::logsource::LogSourceTag;
use crate::parsers::FileFormat;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// One file (or stream) to scan.
#[derive(Clone, Debug)]
pub struct ScanTarget {
    pub path: PathBuf,
    /// Shown in the `LogFile` column.
    pub display_name: String,
    /// Tags added to every event of this target (live analysis: a path the user named for a logsource).
    pub extra_tags: Vec<LogSourceTag>,
    /// A forced format (`--log-format`), otherwise detected.
    pub format: Option<FileFormat>,
}

impl ScanTarget {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            display_name: path.display().to_string(),
            extra_tags: Vec::new(),
            format: None,
        }
    }
}

/// Why a file was not scanned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Empty,
    Binary,
    UnsupportedCompression,
    NotALogFile,
    UnrecognizedFormat,
    Unreadable(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::Empty => write!(f, "empty file"),
            SkipReason::Binary => write!(f, "binary file"),
            SkipReason::UnsupportedCompression => {
                write!(f, "unsupported compression (only .gz is read)")
            }
            SkipReason::NotALogFile => write!(f, "not a text log file"),
            SkipReason::UnrecognizedFormat => write!(f, "unrecognized log format"),
            SkipReason::Unreadable(e) => write!(f, "could not read: {e}"),
        }
    }
}

/// Enumerate the files under `-d` (recursively) or the single `-f` file.
pub fn enumerate(path: &Path, forced_format: Option<FileFormat>) -> Vec<ScanTarget> {
    let mut out = Vec::new();
    if path.is_file() {
        let mut t = ScanTarget::new(path);
        t.format = forced_format;
        out.push(t);
        return out;
    }
    let mut seen_dirs = std::collections::HashSet::new();
    let mut seen_files = std::collections::HashSet::new();
    walk(path, &mut out, &mut seen_dirs, &mut seen_files);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    for t in &mut out {
        t.format = forced_format.clone();
    }
    out
}

/// Recursive directory walk. Symlinked directories are not followed (a link loop would never
/// end, and a link could pull files from outside the evidence tree into the timeline); a
/// symlinked file is scanned once, however many names it has.
fn walk(
    dir: &Path,
    out: &mut Vec<ScanTarget>,
    seen_dirs: &mut std::collections::HashSet<PathBuf>,
    seen_files: &mut std::collections::HashSet<PathBuf>,
) {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !seen_dirs.insert(canonical) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        crate::errorlog::log_warn(&format!("Could not read directory {}", dir.display()));
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            if p.is_dir() {
                crate::errorlog::log_warn(&format!(
                    "Not following the symbolic link to a directory: {}",
                    p.display()
                ));
                continue;
            }
            if !p.is_file() {
                continue;
            }
        } else if file_type.is_dir() {
            walk(&p, out, seen_dirs, seen_files);
            continue;
        } else if !file_type.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
        if seen_files.insert(canonical) {
            out.push(ScanTarget::new(&p));
        }
    }
}

/// Files that are never logs we can read, by name or extension.
pub fn quick_skip_reason(path: &Path) -> Option<SkipReason> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".xz")
        || name.ends_with(".bz2")
        || name.ends_with(".zst")
        || name.ends_with(".lz4")
        || name.ends_with(".zip")
    {
        return Some(SkipReason::UnsupportedCompression);
    }
    if name.ends_with(".journal")
        || name.ends_with(".journal~")
        || name.starts_with("wtmp")
        || name.starts_with("btmp")
        || name.starts_with("lastlog")
        || name.ends_with(".pcap")
        || name.ends_with(".pcap.gz")
        || name.ends_with(".pcapng")
    {
        return Some(SkipReason::NotALogFile);
    }
    match std::fs::metadata(path) {
        Ok(m) if m.len() == 0 => Some(SkipReason::Empty),
        Ok(_) => None,
        Err(e) => Some(SkipReason::Unreadable(e.to_string())),
    }
}

/// Open a file for line reading, decoding gzip when the name ends with `.gz`.
pub fn open_reader(path: &Path) -> std::io::Result<Box<dyn BufRead + Send>> {
    let file = std::fs::File::open(path)?;
    let is_gz = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"));
    if is_gz {
        let dec = flate2::read::MultiGzDecoder::new(BufReader::new(file));
        Ok(Box::new(BufReader::with_capacity(1 << 16, dec)))
    } else {
        Ok(Box::new(BufReader::with_capacity(1 << 16, file)))
    }
}

/// Read up to `max` non-blank lines (lossy UTF-8, `\r` stripped) for format sniffing; `binary`
/// is set when a NUL byte is seen.
pub fn read_sample(path: &Path, max: usize) -> std::io::Result<(Vec<String>, bool)> {
    let mut reader = open_reader(path)?;
    let mut sample = Vec::new();
    let mut buf = Vec::new();
    let mut control_lines = 0usize;
    let mut first = true;
    while sample.len() < max {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        let line = decode_line(&buf, first);
        first = false;
        if !line.trim().is_empty() {
            if line.chars().any(|c| c.is_control() && c != '\t') {
                control_lines += 1;
            }
            sample.push(line);
        }
    }
    // NUL runs alone do not make a file binary: ext4 zero-fills the tail of a log that was being
    // written when the machine crashed, and that log is exactly the one to keep. Other control
    // bytes in many lines do.
    let binary = !sample.is_empty() && control_lines * 4 >= sample.len();
    Ok((sample, binary))
}

/// Iterate over the lines of a reader as lossy UTF-8 strings without the trailing newline/CR.
pub struct Lines<R: Read> {
    reader: BufReader<R>,
    buf: Vec<u8>,
    first: bool,
}

impl<R: Read> Lines<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::with_capacity(1 << 16, reader),
            buf: Vec::new(),
            first: true,
        }
    }
}

impl<R: Read> Iterator for Lines<R> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.buf.clear();
        match self.reader.read_until(b'\n', &mut self.buf) {
            Ok(0) => None,
            Ok(_) => {
                let line = decode_line(&self.buf, self.first);
                self.first = false;
                Some(Ok(line))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// One raw line as text: NUL bytes dropped (zero-filled blocks), lossy UTF-8, the newline / CR
/// removed and, on the first line of a file, a UTF-8 byte order mark.
fn decode_line(buf: &[u8], first: bool) -> String {
    let text = if buf.contains(&0) {
        let clean: Vec<u8> = buf.iter().copied().filter(|b| *b != 0).collect();
        String::from_utf8_lossy(&clean).into_owned()
    } else {
        String::from_utf8_lossy(buf).into_owned()
    };
    let text = text.trim_end_matches(['\n', '\r']);
    let text = if first {
        text.strip_prefix('\u{feff}').unwrap_or(text)
    } else {
        text
    };
    text.to_string()
}

/// Lossy line iterator over a boxed reader.
pub fn lines(reader: Box<dyn BufRead + Send>) -> Lines<Box<dyn BufRead + Send>> {
    Lines::new(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gz_and_plain_files_are_read_the_same_way() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("syslog");
        std::fs::write(&plain, "line one\r\nline two\n").unwrap();
        let gz = dir.path().join("syslog.2.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&gz).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(b"old one\nold two\n").unwrap();
        enc.finish().unwrap();
        let (s, bin) = read_sample(&plain, 10).unwrap();
        assert_eq!(s, vec!["line one", "line two"]);
        assert!(!bin);
        let got: Vec<String> = lines(open_reader(&gz).unwrap())
            .map(|l| l.unwrap())
            .collect();
        assert_eq!(got, vec!["old one", "old two"]);
        let targets = enumerate(dir.path(), None);
        assert_eq!(targets.len(), 2);
        assert_eq!(
            quick_skip_reason(&dir.path().join("x.xz")),
            Some(SkipReason::Unreadable(
                std::io::Error::from(std::io::ErrorKind::NotFound).to_string()
            ))
            .map(|_| SkipReason::UnsupportedCompression)
        );
    }

    #[test]
    fn binary_files_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("wtmp.bin");
        std::fs::write(&bin, b"\x07\x01\x02abc\x03\n\x04\x05def\n").unwrap();
        let (_, binary) = read_sample(&bin, 10).unwrap();
        assert!(binary);
        // NUL runs alone (a zero-filled block after a crash) are dropped, not fatal; a BOM goes.
        let zero_filled = dir.path().join("syslog");
        let mut bytes = b"\xEF\xBB\xBFOct 26 17:39:01 host sshd[1]: before\n".to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 3000));
        bytes.extend(b"Oct 26 17:45:00 host sshd[999]: Corrupted MAC on input.\n");
        std::fs::write(&zero_filled, &bytes).unwrap();
        let (sample, binary) = read_sample(&zero_filled, 10).unwrap();
        assert!(!binary);
        assert_eq!(
            sample,
            vec![
                "Oct 26 17:39:01 host sshd[1]: before".to_string(),
                "Oct 26 17:45:00 host sshd[999]: Corrupted MAC on input.".to_string()
            ]
        );
        assert_eq!(
            quick_skip_reason(&dir.path().join("wtmp")),
            Some(SkipReason::NotALogFile)
        );
    }
}
