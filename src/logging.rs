use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once, OnceLock};

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

/// The level `init_terminal` installed, readable afterwards via
/// [`terminal_max_level`].
static TERMINAL_LEVEL: OnceLock<LevelFilter> = OnceLock::new();

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

pub(crate) fn ansi_enabled(default: bool) -> bool {
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

/// Recover the level from a line already rendered by [`TunmuxLogFormat`].
///
/// The CLI receives the privileged daemon's log lines as finished text over
/// the control socket, long past the point where a `tracing` subscriber could
/// filter them, so the level has to come back out of the string. Kept next to
/// the formatter that writes it: the two are one format, in one file.
///
/// `None` for anything not shaped like a formatted line, which includes the
/// continuation lines of a multi-line message. Callers decide what to do with
/// those rather than being handed a guess.
pub fn parse_line_level(line: &str) -> Option<Level> {
    // `INFO` and `WARN` are space-padded *inside* their color escape, so a
    // colored line splits into a bare escape followed by the level word.
    // Dropping tokens that strip down to nothing rejoins the two.
    let mut tokens = line
        .split_whitespace()
        .map(strip_ansi)
        .filter(|token| !token.is_empty());

    // Anchor on the timestamp so a stray word in a message body can't be read
    // as a level.
    if !looks_like_timestamp(tokens.next()?) {
        return None;
    }

    match tokens.next()? {
        "TRACE" => Some(Level::TRACE),
        "DEBUG" => Some(Level::DEBUG),
        "INFO" => Some(Level::INFO),
        "WARN" => Some(Level::WARN),
        "ERROR" => Some(Level::ERROR),
        _ => None,
    }
}

/// Whether `token` is shaped like a [`LOG_TIMESTAMP_FORMAT`] timestamp
/// (`2026-06-14T08:18:02Z`). Shape only, no calendar validation: this decides
/// whether a line is one of ours, not whether the date is real.
fn looks_like_timestamp(token: &str) -> bool {
    const TIMESTAMP_LEN: usize = "2026-06-14T08:18:02Z".len();
    token.len() == TIMESTAMP_LEN && token.ends_with('Z')
}

/// Strip the SGR escapes that [`FormattedLevel`] and `format_timestamp` wrap a
/// token in when color is on, so parsing works on colored output too.
fn strip_ansi(token: &str) -> &str {
    let mut token = token;
    while let Some(rest) = token.strip_prefix('\u{1b}') {
        match rest.split_once('m') {
            Some((_, tail)) => token = tail,
            None => return token,
        }
    }
    match token.find('\u{1b}') {
        Some(idx) => &token[..idx],
        None => token,
    }
}

/// The maximum level this process's terminal logging renders, for callers that
/// hold log text produced elsewhere and want to apply the same threshold.
/// `None` means logging is off. Defaults to `INFO` before
/// [`init_terminal`] runs (or in a process that never calls it).
pub fn terminal_max_level() -> Option<Level> {
    TERMINAL_LEVEL
        .get()
        .copied()
        .unwrap_or(LevelFilter::INFO)
        .into_level()
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
    let _ = TERMINAL_LEVEL.set(level);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(ansi_enabled(true))
        .event_format(TunmuxLogFormat::new())
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .finish();
    install_subscriber(subscriber, level);
}

/// Writer that always writes to stderr, used by the privileged service. ANSI
/// is disabled by `init_service` so its lines stay plain text (the daemon's
/// own log file may be piped through other tools).
struct ServiceWriter;

impl Write for ServiceWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if should_suppress_log_write(buf) {
            return Ok(buf.len());
        }
        std::io::stderr().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

/// Logging for the privileged service: like `init_terminal`, but with ANSI
/// disabled (its output isn't a terminal) and its own writer.
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
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    // Finding 2 — Protected log disclosure: create private logs without
    // following a pre-existing symlink, and repair an older log's mode.
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "helper log is not a regular file"
    );
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let file = Arc::new(file);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(ansi_enabled(false))
        .event_format(TunmuxLogFormat::new())
        .with_max_level(level)
        .with_writer(move || SharedFileWriter(file.clone()))
        .finish();
    install_subscriber(subscriber, level);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_line_level, strip_ansi, FormattedLevel};
    use tracing::Level;

    /// A line in the shape `TunmuxLogFormat` writes, using the real level
    /// renderer so the padding and color codes match what the daemon emits.
    fn formatted_line(level: Level, ansi: bool) -> String {
        format!(
            "2026-06-14T08:18:02Z {} some_event field=1 tunmux::privileged: ",
            FormattedLevel::new(&level, ansi)
        )
    }

    #[test]
    fn parses_every_level_plain_and_colored() {
        for level in [
            Level::TRACE,
            Level::DEBUG,
            Level::INFO,
            Level::WARN,
            Level::ERROR,
        ] {
            for ansi in [false, true] {
                assert_eq!(
                    parse_line_level(&formatted_line(level, ansi)),
                    Some(level),
                    "level={level} ansi={ansi}"
                );
            }
        }
    }

    #[test]
    fn rejects_lines_that_are_not_ours() {
        // Continuation line of a multi-line message (e.g. the network overview
        // table), and a message whose body merely mentions a level word.
        assert_eq!(parse_line_level("INTERFACE  MTU   ADDRESSES"), None);
        assert_eq!(parse_line_level(""), None);
        assert_eq!(parse_line_level("something DEBUG else"), None);
    }

    #[test]
    fn rejects_timestamp_without_a_level() {
        assert_eq!(parse_line_level("2026-06-14T08:18:02Z hello world"), None);
    }

    #[test]
    fn strip_ansi_unwraps_both_ends() {
        assert_eq!(strip_ansi("\x1b[34mDEBUG\x1b[0m"), "DEBUG");
        assert_eq!(
            strip_ansi("\x1b[2m2026-06-14T08:18:02Z\x1b[0m"),
            "2026-06-14T08:18:02Z"
        );
        assert_eq!(strip_ansi("plain"), "plain");
    }
}
