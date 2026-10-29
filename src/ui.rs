//! Building blocks for the text wgd prints: styled spans, key-value blocks,
//! tables and notes.
//!
//! Renderers say what a piece of text is (a [`Role`]); a [`RenderCtx`],
//! decided once for the stream the text goes to, turns roles into ANSI styles
//! or leaves them out. Column widths are measured in terminal cells of the
//! unstyled text, so neither escapes nor non-ASCII characters shift a column,
//! and the last column of a table is never padded.

use std::io::IsTerminal;

use anstyle::{AnsiColor, Style};
use unicode_width::UnicodeWidthStr;

/// What a piece of text is. [`RenderCtx`] maps it to a style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A field label, bold like `wg show` prints it.
    Label,
    /// The `interface` label of a `wg show` block.
    InterfaceLabel,
    /// The interface name of a `wg show` block.
    Interface,
    /// The `peer` label of a `wg show` block.
    PeerLabel,
    /// A peer's public key in a `wg show` block.
    Peer,
    /// Byte and duration units, so the number stays the thing you read first.
    Unit,
    /// Table headers and rules, quieter than the data they frame.
    Frame,
    /// Something that is not in effect. wgd greys out every inactive
    /// entry the same way, so what is active stands out.
    Muted,
    /// Something the user should look at.
    Warn,
}

impl Role {
    /// The palette `wg show` uses on a terminal, so a wgd tunnel looks the
    /// same as one inspected with `wg` directly.
    fn style(self) -> Style {
        let fg = |color: AnsiColor| Style::new().fg_color(Some(color.into()));
        match self {
            Role::Label => Style::new().bold(),
            Role::InterfaceLabel => fg(AnsiColor::Green).bold(),
            Role::Interface => fg(AnsiColor::Green),
            Role::PeerLabel => fg(AnsiColor::Yellow).bold(),
            Role::Peer => fg(AnsiColor::Yellow),
            Role::Unit => fg(AnsiColor::Cyan),
            Role::Frame => fg(AnsiColor::BrightBlack),
            Role::Muted => Style::new().dimmed(),
            Role::Warn => fg(AnsiColor::Yellow).bold(),
        }
    }
}

/// Whether rendered text carries ANSI escapes. Decide it once per output
/// stream and pass it down; nothing below this asks the terminal itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderCtx {
    ansi: bool,
}

impl RenderCtx {
    /// No escapes: files, pipes, `wgd doctor` reports.
    pub const fn plain() -> Self {
        Self { ansi: false }
    }

    /// Escapes regardless of the terminal, for tests of the styled output.
    #[cfg(test)]
    pub const fn ansi() -> Self {
        Self { ansi: true }
    }

    /// Color when stdout is a terminal; `WGD_LOG_COLOR` overrides in either
    /// direction, matching the logger.
    pub fn stdout() -> Self {
        Self {
            ansi: crate::logging::ansi_enabled(std::io::stdout().is_terminal()),
        }
    }

    /// Like [`RenderCtx::stdout`], for text printed to stderr.
    pub fn stderr() -> Self {
        Self {
            ansi: crate::logging::ansi_enabled(std::io::stderr().is_terminal()),
        }
    }

    pub fn paint(&self, text: &str, role: Role) -> String {
        if !self.ansi || text.is_empty() {
            return text.to_string();
        }
        let style = role.style();
        format!("{style}{text}{style:#}")
    }
}

/// A warning for stderr, styled when stderr is a terminal.
pub fn warning(text: &str) -> String {
    RenderCtx::stderr().paint(text, Role::Warn)
}

/// A run of text with one optional role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub role: Option<Role>,
}

impl Span {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            role: None,
        }
    }

    pub fn styled(text: impl Into<String>, role: Role) -> Self {
        Self {
            text: text.into(),
            role: Some(role),
        }
    }

    /// Display width in terminal cells, escapes excluded.
    pub fn width(&self) -> usize {
        self.text.width()
    }

    fn paint(&self, ctx: &RenderCtx) -> String {
        match self.role {
            Some(role) => ctx.paint(&self.text, role),
            None => self.text.clone(),
        }
    }
}

impl From<&str> for Span {
    fn from(text: &str) -> Self {
        Span::plain(text)
    }
}

impl From<String> for Span {
    fn from(text: String) -> Self {
        Span::plain(text)
    }
}

/// Spans printed next to each other on one line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Line(pub Vec<Span>);

impl Line {
    pub fn paint(&self, ctx: &RenderCtx) -> String {
        self.0.iter().map(|span| span.paint(ctx)).collect()
    }
}

impl From<Span> for Line {
    fn from(span: Span) -> Self {
        Line(vec![span])
    }
}

impl From<Vec<Span>> for Line {
    fn from(spans: Vec<Span>) -> Self {
        Line(spans)
    }
}

impl From<&str> for Line {
    fn from(text: &str) -> Self {
        Span::plain(text).into()
    }
}

impl From<String> for Line {
    fn from(text: String) -> Self {
        Span::plain(text).into()
    }
}

/// Something that renders to whole lines. Every line written ends in `\n`.
pub trait Component {
    fn render(&self, ctx: &RenderCtx, out: &mut String);
}

impl Component for Line {
    fn render(&self, ctx: &RenderCtx, out: &mut String) {
        out.push_str(&self.paint(ctx));
        out.push('\n');
    }
}

/// `label: value` lines in `wg show` layout: an optional heading at the left
/// margin, the rows below it indented by two spaces.
#[derive(Debug, Clone, Default)]
pub struct KeyValue {
    heading: Option<(Span, Line)>,
    rows: Vec<(Span, Line)>,
}

impl KeyValue {
    pub fn with_heading(label: Span, value: impl Into<Line>) -> Self {
        Self {
            heading: Some((label, value.into())),
            rows: Vec::new(),
        }
    }

    /// Add a row with a bold label.
    pub fn row(&mut self, label: &str, value: impl Into<Line>) {
        self.rows
            .push((Span::styled(label, Role::Label), value.into()));
    }
}

impl Component for KeyValue {
    fn render(&self, ctx: &RenderCtx, out: &mut String) {
        if let Some((label, value)) = &self.heading {
            out.push_str(&format!("{}: {}\n", label.paint(ctx), value.paint(ctx)));
        }
        for (label, value) in &self.rows {
            out.push_str(&format!("  {}: {}\n", label.paint(ctx), value.paint(ctx)));
        }
    }
}

/// Between two cells of a row.
const COLUMN_SEPARATOR: &str = " | ";
/// Where the dashed rule under the header crosses a column separator.
const RULE_JUNCTION: &str = "-+-";

#[derive(Debug, Clone)]
struct Row {
    cells: Vec<Span>,
    muted: bool,
}

/// Left-aligned columns, each as wide as its widest cell or header, separated
/// by ` | ` with a `-+-` rule under the header. A blank line above keeps the
/// table off the text before it.
#[derive(Debug, Clone)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Row>,
    indent: usize,
}

impl Table {
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|header| header.to_string()).collect(),
            rows: Vec::new(),
            indent: 0,
        }
    }

    /// Spaces in front of every line.
    pub fn indent(mut self, indent: usize) -> Self {
        self.indent = indent;
        self
    }

    pub fn row(&mut self, cells: Vec<Span>) {
        self.rows.push(Row {
            cells,
            muted: false,
        });
    }

    /// A row that is not in effect. The whole row is dimmed; the cells' own
    /// roles are dropped.
    pub fn muted_row(&mut self, cells: Vec<Span>) {
        self.rows.push(Row { cells, muted: true });
    }

    fn widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self.headers.iter().map(|header| header.width()).collect();
        for row in &self.rows {
            for (index, cell) in row.cells.iter().enumerate() {
                if let Some(width) = widths.get_mut(index) {
                    *width = (*width).max(cell.width());
                }
            }
        }
        widths
    }

    /// Join already painted cells, padding by their unpainted width. The last
    /// cell is not padded.
    fn join(&self, cells: &[(String, usize)], widths: &[usize]) -> String {
        let mut line = " ".repeat(self.indent);
        let last = cells.len().saturating_sub(1);
        for (index, (text, width)) in cells.iter().enumerate() {
            if index > 0 && index == last && text.is_empty() {
                // An empty last cell leaves no trailing blank.
                line.push_str(COLUMN_SEPARATOR.trim_end());
            } else if index > 0 {
                line.push_str(COLUMN_SEPARATOR);
            }
            line.push_str(text);
            if index < last {
                let column = widths.get(index).copied().unwrap_or(*width);
                line.push_str(&" ".repeat(column.saturating_sub(*width)));
            }
        }
        line
    }
}

impl Component for Table {
    fn render(&self, ctx: &RenderCtx, out: &mut String) {
        let widths = self.widths();
        let plain = RenderCtx::plain();
        out.push('\n');

        let header: Vec<(String, usize)> = self
            .headers
            .iter()
            .map(|header| (header.clone(), header.width()))
            .collect();
        let header = self.join(&header, &widths);
        let rule = widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join(RULE_JUNCTION);
        for frame in [header, format!("{}{rule}", " ".repeat(self.indent))] {
            let (indent, text) = frame.split_at(self.indent);
            out.push_str(&format!("{indent}{}\n", ctx.paint(text, Role::Frame)));
        }

        for row in &self.rows {
            let cell_ctx = if row.muted { &plain } else { ctx };
            let cells: Vec<(String, usize)> = row
                .cells
                .iter()
                .map(|cell| (cell.paint(cell_ctx), cell.width()))
                .collect();
            let line = self.join(&cells, &widths);
            if row.muted {
                let (indent, text) = line.split_at(self.indent);
                out.push_str(&format!("{indent}{}\n", ctx.paint(text, Role::Muted)));
            } else {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteLevel {
    /// Worth knowing, nothing to do.
    Info,
    /// Something is off and may need the user.
    Warn,
}

/// A standalone remark under the data it is about. Warnings carry a `!`
/// marker so they stand out without color too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub level: NoteLevel,
    pub text: String,
}

impl Note {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            level: NoteLevel::Info,
            text: text.into(),
        }
    }

    pub fn warn(text: impl Into<String>) -> Self {
        Self {
            level: NoteLevel::Warn,
            text: text.into(),
        }
    }
}

impl Component for Note {
    fn render(&self, ctx: &RenderCtx, out: &mut String) {
        match self.level {
            NoteLevel::Info => out.push_str(&self.text),
            NoteLevel::Warn => out.push_str(&ctx.paint(&format!("! {}", self.text), Role::Warn)),
        }
        out.push('\n');
    }
}

/// Render `component` on its own.
#[cfg(test)]
pub fn render(component: &dyn Component, ctx: &RenderCtx) -> String {
    let mut out = String::new();
    component.render(ctx, &mut out);
    out
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Escapes made readable for snapshots: `ESC[1m` becomes `⟨1m⟩`.
    pub fn visible_ansi(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("\x1b[") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = after.find('m').map_or(after.len(), |end| end + 1);
            out.push('⟨');
            out.push_str(&after[..end]);
            out.push('⟩');
            rest = &after[end..];
        }
        out.push_str(rest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::visible_ansi;
    use super::*;

    fn table() -> Table {
        let mut table = Table::new(&["Name", "Note"]);
        table.row(vec!["a".into(), Span::styled("warn", Role::Warn)]);
        table.muted_row(vec!["longer name".into(), Span::styled("x", Role::Warn)]);
        table
    }

    #[test]
    fn plain_table_pads_every_column_but_the_last() {
        insta::assert_snapshot!(render(&table(), &RenderCtx::plain()));
    }

    #[test]
    fn ansi_table_frames_header_and_mutes_whole_rows() {
        insta::assert_snapshot!(visible_ansi(&render(&table(), &RenderCtx::ansi())));
    }

    #[test]
    fn widths_count_terminal_cells_not_bytes() {
        let mut table = Table::new(&["A", "B"]);
        table.row(vec!["Ä — ü".into(), "1".into()]);
        table.row(vec!["abcde".into(), "2".into()]);
        insta::assert_snapshot!(render(&table, &RenderCtx::plain()));
    }

    #[test]
    fn indented_table_indents_frame_and_rows() {
        let mut table = Table::new(&["Service", "DNS"]).indent(2);
        table.muted_row(vec!["Wi-Fi".into(), "1.1.1.1".into()]);
        insta::assert_snapshot!(visible_ansi(&render(&table, &RenderCtx::ansi())));
    }

    #[test]
    fn key_value_follows_the_wg_show_layout() {
        let mut block = KeyValue::with_heading(
            Span::styled("interface", Role::InterfaceLabel),
            Span::styled("wg0", Role::Interface),
        );
        block.row(
            "transfer",
            vec![
                Span::plain("1.25 "),
                Span::styled("GiB", Role::Unit),
                Span::plain(" received"),
            ],
        );
        insta::assert_snapshot!(format!(
            "{}\n{}",
            render(&block, &RenderCtx::plain()),
            visible_ansi(&render(&block, &RenderCtx::ansi()))
        ));
    }

    #[test]
    fn warning_notes_carry_a_marker_without_color() {
        let note = Note::warn("tunnel DNS pulled back");
        assert_eq!(
            render(&note, &RenderCtx::plain()),
            "! tunnel DNS pulled back\n"
        );
        assert_eq!(render(&Note::info("ok"), &RenderCtx::plain()), "ok\n");
    }

    #[test]
    fn plain_context_never_emits_escapes() {
        assert_eq!(RenderCtx::plain().paint("x", Role::Warn), "x");
        assert_eq!(RenderCtx::ansi().paint("", Role::Warn), "");
    }
}
