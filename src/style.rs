//! Terminal styling for human output.
//!
//! Color is opt-in and gated. It is applied only when all of these hold:
//! stdout is a terminal, the `NO_COLOR` environment variable is unset, and
//! the operator has not passed `--no-color`. In every other case the styled
//! renderers emit the exact plain text they always have — piping a report,
//! or running under a test, never sees escape codes and stays byte-identical.

use std::io::IsTerminal;

/// ANSI Select Graphic Rendition codes used by [`Style`].
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const RED: &str = "31";
    pub const GREEN: &str = "32";
    pub const YELLOW: &str = "33";
    pub const CYAN: &str = "36";
}

/// TTY-gated ANSI styling for the human reports.
///
/// Construct once at startup with [`Style::auto`] — from the `--no-color`
/// flag, the `NO_COLOR` environment variable and whether stdout is a
/// terminal — and pass a reference to the `report::render_*` functions.
/// [`Style::plain`] is the always-off form used by tests and library callers
/// that want the historical byte-exact text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    /// An always-plain style: behaves exactly as the renderers always have.
    /// Used where color is never wanted (tests, library callers).
    #[must_use]
    pub const fn plain() -> Self {
        Self { color: false }
    }

    /// A style that always colors, bypassing the TTY/env gate. Only the
    /// crate's own unit tests use this to assert the escape shapes; production
    /// callers construct styles with [`Style::auto`].
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn colored_for_tests() -> Self {
        Self { color: true }
    }

    /// The color decision as a pure predicate: color applies only when the
    /// `--no-color` flag was not given, stdout is a terminal, and `NO_COLOR`
    /// is not set. Factored out of [`Style::auto`] so the gate's truth table
    /// is unit-testable without touching live process state.
    #[must_use]
    const fn from_parts(no_color: bool, is_terminal: bool, no_color_env: bool) -> Self {
        Self {
            color: !no_color && is_terminal && !no_color_env,
        }
    }

    /// A style that colors only when stdout is a terminal, `NO_COLOR` is
    /// unset, and the `--no-color` flag was not given.
    #[must_use]
    pub fn auto(no_color: bool) -> Self {
        Self::from_parts(
            no_color,
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").is_some(),
        )
    }

    /// Whether this style will emit ANSI escapes.
    #[must_use]
    pub const fn colored(self) -> bool {
        self.color
    }

    /// Wrap `text` in the ANSI SGR `code` (e.g. `"32"`); the identity when
    /// plain. Takes `self` by value because [`Style`] is `Copy`.
    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}{}", ansi::RESET)
        } else {
            text.to_string()
        }
    }

    /// Green — a passing/healthy verdict (`PASS`, 2xx, `covers: yes`).
    #[must_use]
    pub fn pass(self, text: impl AsRef<str>) -> String {
        self.paint(ansi::GREEN, text.as_ref())
    }

    /// Red — a failure verdict (a refused connection, 4xx/5xx, `covers: no`,
    /// an expired certificate).
    #[must_use]
    pub fn fail(self, text: impl AsRef<str>) -> String {
        self.paint(ansi::RED, text.as_ref())
    }

    /// Yellow — a warning/anomaly worth attention (3xx, near-expiry, a
    /// changed route path, a truncated body).
    #[must_use]
    pub fn warn(self, text: impl AsRef<str>) -> String {
        self.paint(ansi::YELLOW, text.as_ref())
    }

    /// Cyan — an informational marker (`INFO` severity).
    #[must_use]
    pub fn info(self, text: impl AsRef<str>) -> String {
        self.paint(ansi::CYAN, text.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_is_byte_identical() {
        let style = Style::plain();
        assert!(!style.colored());
        assert_eq!(style.pass("PASS"), "PASS");
        assert_eq!(style.fail("FAIL"), "FAIL");
        assert_eq!(style.warn("warn"), "warn");
        assert_eq!(style.info("info"), "info");
        assert_eq!(style.paint("31", "x"), "x");
    }

    #[test]
    fn colored_wraps_in_the_requested_sgr_code() {
        let style = Style::colored_for_tests();
        assert!(style.colored());
        assert_eq!(style.pass("PASS"), "\x1b[32mPASS\x1b[0m");
        assert_eq!(style.fail("FAIL"), "\x1b[31mFAIL\x1b[0m");
        assert_eq!(style.warn("!"), "\x1b[33m!\x1b[0m");
        assert_eq!(style.info("i"), "\x1b[36mi\x1b[0m");
    }

    #[test]
    fn auto_gate_truth_table_color_only_for_tty_without_escapes() {
        // Color requires all three inputs to allow it: no `--no-color` flag,
        // a terminal, and no `NO_COLOR` environment variable.
        let gate = Style::from_parts;
        assert!(gate(false, true, false).colored(), "TTY, no escapes -> colored");
        assert!(!gate(true, true, false).colored(), "--no-color disables on a TTY");
        assert!(!gate(false, false, false).colored(), "non-TTY stays plain");
        assert!(!gate(false, true, true).colored(), "NO_COLOR disables on a TTY");
        assert!(!gate(true, true, true).colored());
        assert!(!gate(true, false, true).colored());
        assert!(!gate(false, false, true).colored());
        assert!(!gate(true, false, false).colored());
    }
}
