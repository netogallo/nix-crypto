//! Logging infrastructure for nix-crypto.
//!
//! ## Design
//!
//! Logging is split into two layers:
//!
//! - [`LogSink`]: a trait that abstracts **where** log entries are written.
//!   Implementations may fail, returning a `String` error.
//! - [`Logger`]: a concrete struct that enriches log entries with `time` and
//!   `session_id` tags, delegates writing to a [`LogSink`], and handles write
//!   failures by printing to stderr.
//!
//! ## Log levels
//!
//! [`LogLevel`] is ordered `Debug < Info < Warn < Error`. [`FileSink`] uses
//! this ordering to discard entries below a configured minimum level.
//!
//! ## Session ID
//!
//! Each [`Logger`] instance is assigned a random session ID at construction
//! time. This ID is injected as a tag on every log entry, allowing log entries
//! from a single `CryptoNix` instance to be correlated across a session.

use base64::Engine;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The severity level of a log entry.
///
/// Levels are ordered `Debug < Info < Warn < Error`, allowing [`FileSink`]
/// to discard entries below a configured minimum level.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Returns the string representation of the log level.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info  => "INFO",
            LogLevel::Warn  => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    /// Parse a log level from a string. Returns an error if the string is not
    /// a known log level.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "debug" => Ok(LogLevel::Debug),
            "info"  => Ok(LogLevel::Info),
            "warn"  => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            other   => Err(format!(
                "'{}' is not a known log level. Valid levels are: debug, info, warn, error.",
                other
            )),
        }
    }
}

/// Abstracts the sink where log entries are written.
///
/// Implementations are responsible for writing the entry to their backing
/// store (e.g. a file). If writing fails, an error string is returned.
/// The [`Logger`] struct decides what to do with that error (currently it
/// prints to stderr).
pub trait LogSink: Send + Sync {
    fn write(
        &self,
        level: LogLevel,
        message: &str,
        tags: &[(&str, &str)],
    ) -> Result<(), String>;
}

/// A no-op [`LogSink`] that discards all log entries.
///
/// Used as the default when no logging is configured.
pub struct DummySink;

impl LogSink for DummySink {
    fn write(
        &self,
        _level: LogLevel,
        _message: &str,
        _tags: &[(&str, &str)],
    ) -> Result<(), String> {
        Ok(())
    }
}

/// A [`LogSink`] that writes plain-text log entries to a file in append mode.
///
/// Entries below `min_level` are silently discarded. Write failures are
/// returned as `Err(String)` and printed to stderr by [`Logger`].
///
/// Log entries are written in the format:
///
///     [DEBUG] message | time=2026-01-09T21:29:36Z session_id=abc123 key1=value1
pub struct FileSink {
    file: Mutex<std::fs::File>,
    min_level: LogLevel,
}

impl FileSink {
    /// Open a [`FileSink`] at the given path in append mode.
    pub fn open(path: &str, min_level: LogLevel) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("Failed to open log file '{}': {}", path, e))?;

        Ok(FileSink {
            file: Mutex::new(file),
            min_level,
        })
    }
}

impl LogSink for FileSink {
    fn write(
        &self,
        level: LogLevel,
        message: &str,
        tags: &[(&str, &str)],
    ) -> Result<(), String> {
        if level < self.min_level {
            return Ok(());
        }

        let tags_str = tags
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(" ");

        let line = if tags_str.is_empty() {
            format!("[{}] {}\n", level.as_str(), message)
        } else {
            format!("[{}] {} | {}\n", level.as_str(), message, tags_str)
        };

        let mut file = self.file.lock().map_err(|e| {
            format!("Failed to acquire log file lock: {}", e)
        })?;

        file.write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write to log file: {}", e))
    }
}

/// A concrete logger that enriches log entries with `time` and `session_id`
/// tags and delegates writing to a [`LogSink`].
///
/// If the sink returns an error, the error is printed to stderr.
///
/// Each `Logger` instance is assigned a random session ID at construction
/// time, which is injected as a tag on every log entry.
pub struct Logger {
    sink: Box<dyn LogSink>,
    session_id: String,
    min_loglevel: LogLevel,
}

impl Logger {
    /// Construct a new `Logger` with the given sink.
    ///
    /// A random session ID is generated at construction time.
    pub fn new(sink: Box<dyn LogSink>, min_loglevel: LogLevel) -> Self {
        let session_id = format!("{:016x}", rand_session_id());
        Logger { sink, session_id, min_loglevel }
    }

    /// Construct a `Logger` that discards all log entries.
    pub fn dummy() -> Self {
        Logger::new(Box::new(DummySink), LogLevel::Error)
    }

    /// Construct a `Logger` that writes to a file at the given path.
    ///
    /// Entries below `min_level` are silently discarded.
    pub fn file(path: &str, min_level: LogLevel) -> Result<Self, String> {
        let sink = FileSink::open(path, min_level)?;
        Ok(Logger::new(Box::new(sink), min_level))
    }

    /// Returns the session ID assigned to this logger instance.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Log an entry at the given level with the given message and tags.
    ///
    /// The `time` (current UTC time as RFC3339) and `session_id` tags are
    /// injected automatically. If the sink returns an error, it is printed
    /// to stderr.
    pub fn log(&self, level: LogLevel, message: &str, tags: &[(&str, &str)]) {
        let time = current_time_rfc3339();

        let mut all_tags = vec![
            ("time", time.as_str()),
            ("session_id", self.session_id.as_str()),
        ];
        all_tags.extend_from_slice(tags);

        if let Err(e) = self.sink.write(level, message, &all_tags) {
            eprintln!("nix-crypto logger error: {}", e);
        }
    }

    pub fn to_log_identifier(&self, raw: &Vec<u8>) -> String {
        /// Todo: this function should use a safe cryptographic
        /// hash to hash the value. Afterwards return the
        /// base64 encoding of the hash as a string

        if self.min_loglevel <= LogLevel::Debug {
            base64::engine::general_purpose::STANDARD.encode(&raw)
        } else {
            "<scrubbed>".to_string()
        }
    }
}

/// Format the current UTC time as an RFC3339 string using only `std::time`.
fn current_time_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    let (year, month, day) = days_to_ymd(days);

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, h, m, s)
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Uses the algorithm from <http://howardhinnant.github.io/date_algorithms.html>.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Generate a random session ID using the system time as a seed.
///
/// This avoids pulling in the `rand` crate for a simple use case.
fn rand_session_id() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Mix with a simple hash to reduce collisions between rapid invocations.
    (nanos as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}
