//! TTY-gated progress display for long-running multi-target sweeps.
//!
//! Progress is written to **stderr** — never stdout, so `--json`, `--csv`
//! and human data survive intact — and only when stderr is a terminal and
//! the visual-affordance switches (`NO_COLOR` / `--no-color`) did not turn
//! the polish off. Each completed unit overwrites the same line with `\r`;
//! the final line ends with a newline so the next shell prompt is never
//! glued to a half-finished row. When the gate is closed — or the sweep has
//! fewer than two targets, where "1/1" would just be noise — nothing is
//! written at all.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Whether a progress display should be shown for a `total`-unit run.
/// Factored out of [`Progress::new`] so the gate's truth table is testable
/// without touching live process state.
const fn should_show(total: usize, no_color_flag: bool, no_color_env: bool, stderr_tty: bool) -> bool {
    // Only multi-target sweeps get a counter ("1/1", say, is noise on a big
    // diagnosis), and only when the user can actually watch stderr.
    total > 1 && !no_color_flag && !no_color_env && stderr_tty
}

/// A counted progress poster for a multi-target sweep.
pub struct Progress {
    shown: bool,
    done: AtomicUsize,
    total: usize,
}

impl Progress {
    /// Start a progress display for `total` units. `no_color_flag` is the
    /// CLI `--no-color` flag; together with `NO_COLOR` it counts as "the
    /// user asked to quiet the visual affordances".
    pub fn new(total: usize, no_color_flag: bool) -> Self {
        let shown = should_show(
            total,
            no_color_flag,
            std::env::var_os("NO_COLOR").is_some(),
            std::io::stderr().is_terminal(),
        );
        Self {
            shown,
            done: AtomicUsize::new(0),
            total,
        }
    }

    /// Advance one unit and redraw: `... 3/10 hostname` on one line.
    pub fn step(&self, label: &str) {
        if !self.shown {
            return;
        }
        let done = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        eprint!("\r  {done}/{} {label}", self.total);
    }

    /// Terminate whichever progress line is on screen with a newline.
    pub fn finish(&self) {
        if !self.shown {
            return;
        }
        let done = self.done.load(Ordering::Relaxed);
        eprintln!("\r  {done}/{} complete", self.total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_gate_requires_multi_target_terminal_and_no_quiet_switch() {
        let gate = should_show;
        // Show: >1 target, no flags/env, stderr is a terminal.
        assert!(gate(2, false, false, true), "watchable multi-target sweep");
        // Never for a single target ("1/1" is noise).
        assert!(!gate(1, false, false, true));
        assert!(!gate(0, false, false, true));
        // Any quiet/untrackable condition suppresses it.
        assert!(!gate(2, true, false, true), "--no-color also quiets progress");
        assert!(!gate(2, false, true, true), "NO_COLOR quiets progress");
        assert!(!gate(2, false, false, false), "non-TTY stderr stays clean");
        assert!(!gate(2, true, true, false));
    }

    #[test]
    fn silent_progress_is_a_noop() {
        // A suppressed progress must never touch stderr or advance its count.
        let progress = Progress {
            shown: false,
            done: AtomicUsize::new(0),
            total: 3,
        };
        progress.step("a");
        progress.step("b");
        progress.finish();
        assert_eq!(progress.done.load(Ordering::Relaxed), 0);
    }
}
