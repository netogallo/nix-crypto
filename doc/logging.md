# Logging in nix-crypto

## Overview

nix-crypto supports optional structured logging. Log entries are written in
plain text to a file and are enriched with a timestamp and a session ID on
every entry. Logging is disabled by default — no log file is written unless
explicitly configured.

Logging is implemented in `nix-crypto-core` and is available to both the
nix plugin and the `nix-crypto-service` CLI tool.

---

## User guide

### Logging in the nix plugin

When using the nix plugin, logging is configured via the
`--option extra-cryptonix-args` flag passed to `nix`. Two optional parameters
control logging:

| Parameter | Description |
|---|---|
| `log-file=<path>` | Path to the log file. If absent, logging is disabled. |
| `log-level=<level>` | Minimum log level. One of `debug`, `info`, `warn`, `error`. Defaults to `info`. |

#### Example

    nix \
      --extra-experimental-features nix-command \
      --option plugin-files /path/to/libnix_crypto_plugin.so \
      --option extra-cryptonix-args "mode=filesystem&store-path=/tmp/secrets&log-file=/tmp/nix-crypto.log&log-level=debug" \
      eval --expr '...'

This will write all log entries at `debug` level and above to
`/tmp/nix-crypto.log`.

#### Notes

- If `log-file` is not specified, no log file is written.
- If `log-level` is not specified, it defaults to `info`.
- The log file is opened in **append mode** — existing content is preserved
  across multiple nix invocations.
- Each nix invocation that loads the plugin creates a new `CryptoNix` instance
  with a fresh session ID. Log entries from different invocations can be
  distinguished by their `session_id` tag.

---

### Logging in `nix-crypto-service`

When using the `nix-crypto-service` CLI tool, logging is configured via two
optional flags:

| Flag | Description |
|---|---|
| `--log-file <path>` | Path to the log file. If absent, logging is disabled. |
| `--log-level <level>` | Minimum log level. One of `debug`, `info`, `warn`, `error`. Defaults to `info`. |

#### Example

    nix-crypto-service export secret \
      --sled-store /tmp/secrets \
      --identity-type openssl-pkey \
      --openssl-pkey-type rsa \
      --openssl-pkey-id "name=my-key&vault=openssl" \
      --output-file /tmp/my-key.pem \
      --log-file /tmp/nix-crypto-service.log \
      --log-level debug

This will write all log entries at `debug` level and above to
`/tmp/nix-crypto-service.log`.

#### Notes

- If `--log-file` is not specified, no log file is written.
- If `--log-level` is not specified, it defaults to `info`.
- The log file is opened in **append mode** — existing content is preserved
  across multiple invocations.
- Each invocation of `nix-crypto-service` creates a new `CryptoNix` instance
  with a fresh session ID.

---

### Log entry format

Log entries are written as plain text lines in the following format:

    [LEVEL] message | key1=value1 key2=value2 ...

The following tags are injected automatically on every entry:

| Tag | Description |
|---|---|
| `time` | The current UTC time in RFC3339 format (e.g. `2026-01-09T21:29:36Z`). |
| `session_id` | A random hex string identifying the current `CryptoNix` instance. |

Additional tags may be present depending on the log entry. For example, a
`store get` entry includes `key` and `value` tags (base64-encoded).

#### Example log entries

    [DEBUG] store get | time=2026-01-09T21:29:36Z session_id=3f4a1b2c8e9d0f1a key=dGVzdA== value=dGVzdA==
    [INFO]  store put | time=2026-01-09T21:29:36Z session_id=3f4a1b2c8e9d0f1a key=dGVzdA==

---

### Log levels

| Level | Description |
|---|---|
| `debug` | Fine-grained diagnostic information, including raw store keys and values (base64-encoded). |
| `info` | General operational information. |
| `warn` | Warnings about unexpected but recoverable conditions. |
| `error` | Errors that may indicate a problem. |

Entries below the configured minimum level are silently discarded.

---

## Implementation details

### Architecture

Logging is implemented in `nix-crypto-core/src/logger.rs` and is split into
two layers:

- **`LogSink` trait**: abstracts *where* log entries are written. Implementations
  may fail, returning a `String` error. The `Logger` struct decides what to do
  with that error.
- **`Logger` struct**: a concrete struct that enriches log entries with `time`
  and `session_id` tags, delegates writing to a `LogSink`, and handles write
  failures by printing to stderr.

This separation allows the enrichment and error-handling logic to be fixed in
`Logger` while the sink (file, no-op, or future implementations) remains
pluggable.

### `LogSink` trait

    pub trait LogSink: Send + Sync {
        fn write(
            &self,
            level: LogLevel,
            message: &str,
            tags: &[(&str, &str)],
        ) -> Result<(), String>;
    }

Implementations:

- **`DummySink`**: a no-op sink that discards all entries. Used when no
  `log-file` is configured.
- **`FileSink`**: writes plain-text entries to a file opened in append mode.
  Entries below `min_level` are silently discarded. The file handle is wrapped
  in a `Mutex` for thread safety.

### `Logger` struct

    pub struct Logger {
        sink: Box<dyn LogSink>,
        session_id: String,
    }

- Constructed via `Logger::new(sink)`, `Logger::dummy()`, or
  `Logger::file(path, min_level)`.
- The `session_id` is a random 64-bit integer formatted as a 16-character hex
  string, generated at construction time using the system clock as a seed.
- The `log` method injects `time` and `session_id` tags, then delegates to
  `sink.write`. If `sink.write` returns an error, it is printed to stderr via
  `eprintln!`.
- The `session_id` method exposes the session ID so that callers can include
  it in their own log entries or error messages.

### `LogLevel`

    pub enum LogLevel { Debug, Info, Warn, Error }

- Derives `PartialOrd` and `Ord` so levels can be compared numerically
  (`Debug < Info < Warn < Error`).
- `FileSink` uses this ordering to discard entries below `min_level`.
- `LogLevel::from_str` parses `"debug"`, `"info"`, `"warn"`, `"error"`.
- `LogLevel::as_str` returns the uppercase string representation used in log
  entries (e.g. `"DEBUG"`).

### Session ID generation

The session ID is generated using the subsecond nanoseconds of the system
clock, mixed with a linear congruential hash to reduce collisions between
rapid invocations:

    fn rand_session_id() -> u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        (nanos as u64)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)
    }

This avoids pulling in the `rand` crate for a simple use case. It is not
cryptographically secure and is not intended to be — it is only used for
correlating log entries within a session.

### Integration with `CryptoNix`

`CryptoNix` holds a `Logger` instance:

    pub struct CryptoNix {
        store: Box<dyn CryptoStore>,
        logger: Logger,
    }

- `CryptoNix::with_error` always uses `Logger::dummy()`.
- `CryptoNix::from_sled_config` accepts a `Logger` parameter.
- `CryptoNix::with_args` parses `log-file` and `log-level` from the args
  string via `LoggerConfig::from_parsed_args`, constructs the appropriate
  logger, and passes it to `from_sled_config`.

Currently, the logger is used in `CryptoNix::get` to log store reads at
`debug` level, including the base64-encoded raw key and value.

### Integration with `nix-crypto-service`

In `nix-crypto-service`, the logger is constructed in `export::resolve_logger`
from the `--log-file` and `--log-level` CLI flags, and stored in `ExportArgs`.
It is then passed to `CryptoNix::from_sled_config` in `export::run_secret`.

### `LoggerConfig` in `nix-crypto-core`

`LoggerConfig` in `nix-crypto-core/src/args.rs` is responsible for parsing
logger configuration from the args map used by the nix plugin:

    pub struct LoggerConfig {
        pub log_file: Option<String>,
        pub log_level: LogLevel,
    }

- `LoggerConfig::from_parsed_args` reads `log-file` and `log-level` from the
  parsed args map.
- `LoggerConfig::to_logger` constructs the appropriate `Logger` — either
  `Logger::dummy()` or `Logger::file(path, level)`.

### Write failure handling

If a `LogSink` implementation fails to write an entry (e.g. due to a full
disk or a permissions error), it returns `Err(String)`. The `Logger::log`
method catches this and prints the error to stderr:

    if let Err(e) = self.sink.write(level, message, &all_tags) {
        eprintln!("nix-crypto logger error: {}", e);
    }

This ensures that logging failures are visible but do not propagate as errors
into the main application logic.
