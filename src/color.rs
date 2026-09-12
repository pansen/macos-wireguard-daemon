//! ANSI coloring for `tunmux status` output.
//!
//! Two renderers live here. [`wg_show`] reproduces the palette `wg show` uses
//! when it writes to a terminal (green interface, yellow peer, bold field
//! labels, cyan units) so a tunmux tunnel looks the same as one inspected with
//! `wg` directly. [`tables`] greys out the column headers and rules of the
//! summary table and of the network overview, keeping the frame quieter than
//! the data inside it.
//!
//! Both take the plain text the privileged service produced and repaint it on
//! the client side: the daemon and the per-interface helper write into a socket,
//! so only the CLI knows whether a terminal is on the other end.

use std::io::IsTerminal;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const GREY: &str = "\x1b[90m";

/// Byte and duration units `format_wg_show` emits. Colored cyan the way
/// `wg show` colors them, so the number stays the thing you read first.
const UNITS: &[&str] = &[
    "B", "KiB", "MiB", "GiB", "TiB", "second", "seconds", "minute", "minutes", "hour", "hours",
    "day", "days",
];

/// Whether stdout should carry ANSI escapes. A terminal gets color by default;
/// `TUNMUX_LOG_COLOR` overrides in either direction, matching the logger.
pub fn enabled() -> bool {
    crate::logging::ansi_enabled(std::io::stdout().is_terminal())
}

/// Grey, for the column headers and rules of tables tunmux prints itself.
pub fn table_frame(text: &str) -> String {
    paint_table_frame(text, enabled())
}

fn paint_table_frame(text: &str, ansi: bool) -> String {
    if ansi {
        format!("{GREY}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Repaint `wg show` output in wg's own colors.
pub fn wg_show(text: &str) -> String {
    paint_wg_show(text, enabled())
}

fn paint_wg_show(text: &str, ansi: bool) -> String {
    if !ansi {
        return text.to_string();
    }
    text.lines()
        .map(wg_show_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn wg_show_line(line: &str) -> String {
    let Some((label_part, value)) = line.split_once(": ") else {
        return line.to_string();
    };
    let indent = &label_part[..label_part.len() - label_part.trim_start().len()];
    let label = label_part.trim_start();

    match label {
        "interface" => format!("{GREEN}{BOLD}{label}{RESET}: {GREEN}{value}{RESET}"),
        "peer" => format!("{YELLOW}{BOLD}{label}{RESET}: {YELLOW}{value}{RESET}"),
        _ => format!("{indent}{BOLD}{label}{RESET}: {}", color_units(value)),
    }
}

/// Cyan the unit words in a value, leaving the numbers at default weight:
/// `1.25 GiB received` or `every 25 seconds`.
fn color_units(value: &str) -> String {
    value
        .split(' ')
        .map(|token| {
            let (word, trailer) = split_trailing_punctuation(token);
            if UNITS.contains(&word) {
                format!("{CYAN}{word}{RESET}{trailer}")
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn split_trailing_punctuation(token: &str) -> (&str, &str) {
    token.split_at(token.trim_end_matches([',', ';']).len())
}

/// Grey out the column headers and rules of every table in `text`. A header is
/// the line directly above a rule of dashes, which is how both the summary
/// table and the helper's network overview render one.
pub fn tables(text: &str) -> String {
    paint_tables(text, enabled())
}

fn paint_tables(text: &str, ansi: bool) -> String {
    if !ansi {
        return text.to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let heads_a_table =
                lines.get(index + 1).is_some_and(|next| is_rule(next)) && !line.trim().is_empty();
            if heads_a_table || is_rule(line) {
                paint_table_frame(line, true)
            } else {
                (*line).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A table rule: dashes plus whatever column separators the renderer uses.
fn is_rule(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.contains('-') && trimmed.chars().all(|c| matches!(c, '-' | '+' | '|' | ' '))
}

#[cfg(test)]
mod tests {
    use super::{color_units, is_rule, paint_tables, paint_wg_show, wg_show_line};

    #[test]
    fn interface_and_peer_lines_carry_wg_colors() {
        assert_eq!(
            wg_show_line("interface: wgconf0"),
            "\x1b[32m\x1b[1minterface\x1b[0m: \x1b[32mwgconf0\x1b[0m"
        );
        assert_eq!(
            wg_show_line("peer: abc="),
            "\x1b[33m\x1b[1mpeer\x1b[0m: \x1b[33mabc=\x1b[0m"
        );
    }

    #[test]
    fn indented_labels_stay_indented_and_bold() {
        assert_eq!(
            wg_show_line("  listening port: 62401"),
            "  \x1b[1mlistening port\x1b[0m: 62401"
        );
    }

    #[test]
    fn units_are_cyan_and_numbers_are_not() {
        assert_eq!(
            color_units("1.25 GiB received, 4.21 GiB sent"),
            "1.25 \x1b[36mGiB\x1b[0m received, 4.21 \x1b[36mGiB\x1b[0m sent"
        );
        assert_eq!(
            color_units("every 25 seconds"),
            "every 25 \x1b[36mseconds\x1b[0m"
        );
        // A bare endpoint has no units to paint.
        assert_eq!(color_units("23.88.101.22:51821"), "23.88.101.22:51821");
    }

    #[test]
    fn allowed_ips_keep_the_default_color() {
        assert_eq!(
            wg_show_line("  allowed ips: 10.66.77.0/24, 100.64.0.1/32"),
            "  \x1b[1mallowed ips\x1b[0m: 10.66.77.0/24, 100.64.0.1/32"
        );
    }

    #[test]
    fn rules_are_recognized_for_both_table_styles() {
        assert!(is_rule("-------+--------"));
        assert!(is_rule("----  ----  ----"));
        assert!(!is_rule("Instance | Provider"));
        assert!(!is_rule(""));
    }

    #[test]
    fn table_header_and_its_rule_turn_grey() {
        let table = "Routes\nDESTINATION  VIA\n-----------  ---\n1.2.3.4/32   utun4";
        let colored = paint_tables(table, true);
        assert!(colored.contains("\x1b[90mDESTINATION  VIA\x1b[0m"));
        assert!(colored.contains("\x1b[90m-----------  ---\x1b[0m"));
        // Section titles and data rows keep the terminal's default color.
        assert!(colored.starts_with("Routes\n"));
        assert!(colored.ends_with("1.2.3.4/32   utun4"));
    }

    #[test]
    fn disabled_color_returns_the_text_untouched() {
        let wg = "interface: wgconf0\n  transfer: 1.25 GiB received, 0 B sent";
        assert_eq!(paint_wg_show(wg, false), wg);
        let table = "A  B\n-  -\n1  2";
        assert_eq!(paint_tables(table, false), table);
    }
}
