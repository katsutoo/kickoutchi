//! Runtime configuration and safe defaults.

use std::time::Duration;

/// User-tunable runtime settings.
///
/// For now this only carries the UI tick cadence. Loading from a config file and
/// the full preference set (sort order, refresh interval, protected processes)
/// come later. The type exists now so every later feature reads one shared
/// settings source instead of scattering literals across the code base.
#[derive(Debug)]
pub(crate) struct Config {
    /// Upper bound on how long the event loop waits for input before looping.
    ///
    /// This is a latency cap, not a busy-poll: queued input wakes the loop
    /// immediately, so the interval only bounds idle wait time. It is kept small
    /// so any per-tick work added later stays responsive.
    pub(crate) tick_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(250),
        }
    }
}
