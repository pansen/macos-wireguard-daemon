use std::cell::RefCell;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};

use time::macros::format_description;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, UtcTime};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::registry::LookupSpan;

const LOG_TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
const DEBUG_ENV: &str = "TUNMUX_DEBUG";
pub(crate) const COLOR_ENV: &str = "TUNMUX_LOG_COLOR";
const GOTATUN_UAPI_CONNECTION_TARGET: &str = "gotatun::device::uapi";
const GOTATUN_UAPI_CONNECTION_MESSAGE: &str = "New UAPI connection on unix socket";

static SUPPRESS_GOTATUN_UAPI_CONNECTION_LOGS: AtomicUsize = AtomicUsize::new(0);

pub struct GotatunUapiConnectionLogSuppression;

impl Drop for GotatunUapiConnectionLogSuppression {
    fn drop(&mut self) {
        SUPPRESS_GOTATUN_UAPI_CONNECTION_LOGS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn suppress_gotatun_uapi_connection_logs() -> GotatunUapiConnectionLogSuppression {
    SUPPRESS_GOTATUN_UAPI_CONNECTION_LOGS.fetch_add(1, Ordering::Relaxed);
    GotatunUapiConnectionLogSuppression
}

fn should_suppress_log_write(buf: &[u8]) -> bool {
    if SUPPRESS_GOTATUN_UAPI_CONNECTION_LOGS.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let Ok(line) = std::str::from_utf8(buf) else {
        return false;
    };
    line.contains(GOTATUN_UAPI_CONNECTION_TARGET) && line.contains(GOTATUN_UAPI_CONNECTION_MESSAGE)
}

fn level_from_env_or_default(default: LevelFilter) -> LevelFilter {
    if debug_enabled() {
        return LevelFilter::DEBUG;
    }
    let Ok(value) = std::env::var("RUST_LOG") else {
        return default;
    };
    let lower = value.to_ascii_lowercase();
    if lower.contains("trace") {
        LevelFilter::TRACE
    } else if lower.contains("debug") {
        LevelFilter::DEBUG
    } else if lower.contains("warn") {
        LevelFilter::WARN
    } else if lower.contains("error") {
        LevelFilter::ERROR
    } else if lower.contains("off") {
        LevelFilter::OFF
    } else {
        LevelFilter::INFO
    }
}

fn ansi_enabled(default: bool) -> bool {
    let Some(value) = std::env::var_os(COLOR_ENV) else {
        return default;
    };
    match value.to_string_lossy().to_ascii_lowercase().as_str() {
        "always" | "1" | "true" | "yes" | "on" => true,
        "never" | "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

pub fn enable_debug() {
    std::env::set_var(DEBUG_ENV, "1");
}

pub fn debug_enabled() -> bool {
    std::env::var_os(DEBUG_ENV).is_some()
}

fn to_log_level_filter(level: LevelFilter) -> log::LevelFilter {
    match level {
        LevelFilter::OFF => log::LevelFilter::Off,
        LevelFilter::ERROR => log::LevelFilter::Error,
        LevelFilter::WARN => log::LevelFilter::Warn,
        LevelFilter::INFO => log::LevelFilter::Info,
        LevelFilter::DEBUG => log::LevelFilter::Debug,
        LevelFilter::TRACE => log::LevelFilter::Trace,
    }
}

struct TunmuxLogFormat {
    timer: UtcTime<&'static [time::format_description::FormatItem<'static>]>,
}

impl TunmuxLogFormat {
    fn new() -> Self {
        Self {
            timer: UtcTime::new(LOG_TIMESTAMP_FORMAT),
        }
    }
}

impl<S, N> FormatEvent<S, N> for TunmuxLogFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let normalized_meta = event.normalized_metadata();
        let meta = normalized_meta.as_ref().unwrap_or_else(|| event.metadata());

        self.format_timestamp(&mut writer)?;
        write!(
            writer,
            "{} ",
            FormattedLevel::new(meta.level(), writer.has_ansi_escapes())
        )?;

        if let Some(message) = multiline_message(event) {
            writer.write_str(&message)?;
        } else {
            ctx.format_fields(writer.by_ref(), event)?;
        }
        writer.write_char(' ')?;
        write_dimmed(&mut writer, meta.target())?;
        write_dimmed(&mut writer, ":")?;
        writer.write_char(' ')?;
        writeln!(writer)
    }
}

impl TunmuxLogFormat {
    fn format_timestamp(&self, writer: &mut Writer<'_>) -> fmt::Result {
        if writer.has_ansi_escapes() {
            writer.write_str("\x1b[2m")?;
            self.timer.format_time(writer)?;
            writer.write_str("\x1b[0m ")?;
        } else {
            self.timer.format_time(writer)?;
            writer.write_char(' ')?;
        }
        Ok(())
    }
}

struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

/// Multi-line messages (e.g. the macOS network overview table) are written
/// verbatim. Reading the message straight off the raw event preserves real
/// newlines and ANSI bytes — `ctx.format_fields` would escape control chars as
/// a log-injection guard, mangling the table's colors.
fn multiline_message(event: &Event<'_>) -> Option<String> {
    let mut visitor = MessageVisitor { message: None };
    event.record(&mut visitor);
    visitor.message.filter(|message| message.contains('\n'))
}

struct FormattedLevel<'a> {
    level: &'a Level,
    ansi: bool,
}

impl<'a> FormattedLevel<'a> {
    fn new(level: &'a Level, ansi: bool) -> Self {
        Self { level, ansi }
    }
}

impl fmt::Display for FormattedLevel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match *self.level {
            Level::TRACE => "TRACE",
            Level::DEBUG => "DEBUG",
            Level::INFO => " INFO",
            Level::WARN => " WARN",
            Level::ERROR => "ERROR",
        };

        if !self.ansi {
            return f.write_str(value);
        }

        let color = match *self.level {
            Level::TRACE => "35",
            Level::DEBUG => "34",
            Level::INFO => "32",
            Level::WARN => "33",
            Level::ERROR => "31",
        };
        write!(f, "\x1b[{color}m{value}\x1b[0m")
    }
}

fn write_dimmed(writer: &mut Writer<'_>, value: &str) -> fmt::Result {
    if writer.has_ansi_escapes() {
        write!(writer, "\x1b[2m{value}\x1b[0m")
    } else {
        writer.write_str(value)
    }
}

fn install_subscriber<S>(subscriber: S, level: LevelFilter)
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    static SUBSCRIBER_INIT: Once = Once::new();
    static LOG_TRACER_INIT: Once = Once::new();

    SUBSCRIBER_INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    LOG_TRACER_INIT.call_once(|| {
        let _ = tracing_log::LogTracer::init();
    });

    log::set_max_level(to_log_level_filter(level));
}

pub fn init_terminal(verbose: bool) {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(ansi_enabled(true))
        .event_format(TunmuxLogFormat::new())
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .finish();
    install_subscriber(subscriber, level);
}

// --- Per-request log capture (privileged service) ------------------------------------------
//
// The privileged service installs a subscriber whose writer tees every formatted log line to
// stderr *and*, while a capture is active on the current thread, into a buffer. Request handling
// is synchronous and single-threaded per connection, so a thread-local buffer cleanly scopes the
// captured lines to one request. The captured lines are then streamed back to the calling CLI.

/// Hard cap on bytes captured per request. A verbose/debug session (or unexpected helper output)
/// would otherwise grow this buffer without bound in the privileged daemon. Past the cap, capture
/// stops and a truncation marker is appended when the buffer is drained.
const MAX_CAPTURE_BYTES: usize = 256 * 1024;

struct CaptureBuffer {
    bytes: Vec<u8>,
    truncated: bool,
}

thread_local! {
    static LOG_CAPTURE: RefCell<Option<CaptureBuffer>> = const { RefCell::new(None) };
}

/// Start capturing this thread's formatted log output into a buffer.
pub fn begin_log_capture() {
    LOG_CAPTURE.with(|cell| {
        *cell.borrow_mut() = Some(CaptureBuffer {
            bytes: Vec::new(),
            truncated: false,
        })
    });
}

/// Stop capturing and return the captured output split into lines (without trailing newlines).
pub fn take_log_capture() -> Vec<String> {
    LOG_CAPTURE
        .with(|cell| cell.borrow_mut().take())
        .map(|capture| {
            let mut lines: Vec<String> = String::from_utf8_lossy(&capture.bytes)
                .lines()
                .map(str::to_string)
                .collect();
            if capture.truncated {
                lines.push("(log capture truncated)".to_string());
            }
            lines
        })
        .unwrap_or_default()
}

/// Writer that always writes to stderr and, when a capture is active on this thread, also appends
/// to the thread-local capture buffer.
struct ServiceWriter;

impl Write for ServiceWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if should_suppress_log_write(buf) {
            return Ok(buf.len());
        }
        let _ = std::io::stderr().write_all(buf);
        LOG_CAPTURE.with(|cell| {
            if let Some(capture) = cell.borrow_mut().as_mut() {
                let remaining = MAX_CAPTURE_BYTES.saturating_sub(capture.bytes.len());
                if buf.len() <= remaining {
                    capture.bytes.extend_from_slice(buf);
                } else {
                    capture.bytes.extend_from_slice(&buf[..remaining]);
                    capture.truncated = true;
                }
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

/// Logging for the privileged service: like `init_terminal`, but its writer also captures output
/// per request so it can be streamed back to the calling CLI. ANSI is disabled so captured lines
/// are plain text.
pub fn init_service(verbose: bool) {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(ansi_enabled(false))
        .event_format(TunmuxLogFormat::new())
        .with_max_level(level)
        .with_writer(|| ServiceWriter)
        .finish();
    install_subscriber(subscriber, level);
}

/// Writer over a shared append-mode file handle. Each write is an O_APPEND syscall with no
/// userspace buffering, so log lines are durable and readable by another process immediately.
struct SharedFileWriter(Arc<File>);

impl Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if should_suppress_log_write(buf) {
            return Ok(buf.len());
        }
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

/// Synchronous, line-durable file logging. Used by the gotatun helper so the privileged service
/// can tail its log file and stream it back to the caller without a flush race.
pub fn init_file_sync(path: &str, verbose: bool) -> anyhow::Result<()> {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let file = Arc::new(OpenOptions::new().create(true).append(true).open(path)?);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(ansi_enabled(false))
        .event_format(TunmuxLogFormat::new())
        .with_max_level(level)
        .with_writer(move || SharedFileWriter(file.clone()))
        .finish();
    install_subscriber(subscriber, level);
    Ok(())
}
