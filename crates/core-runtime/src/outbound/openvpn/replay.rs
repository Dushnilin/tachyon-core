//! OpenVPN replay window — port of sing-openvpn `replay_window.go`.
//!
//! Upstream `packet_id_test` (replay.c) rejects duplicate/old packet IDs and
//! long-form timestamps that backtrack; `--replay-window 0` accepts only
//! strictly monotonic packet IDs.

use std::time::{Duration, Instant};

/// Upstream `DEFAULT_SEQ_BACKTRACK`.
pub const DEFAULT_REPLAY_WINDOW_SIZE: u32 = 64;
/// Upstream validation bounds (enforced by the config checker, not here).
#[allow(dead_code)]
pub const MAX_REPLAY_WINDOW_SIZE: u32 = 65_536;
pub const DEFAULT_REPLAY_WINDOW_TIME: Duration = Duration::from_secs(15);
#[allow(dead_code)]
pub const MAX_REPLAY_WINDOW_TIME: Duration = Duration::from_secs(600);

/// `dataReplayWindowParameters`: defaults for unset option values.
pub fn replay_window_parameters(window_size: u32, time_window: Duration) -> (u32, Duration) {
    let window_size = if window_size == 0 {
        DEFAULT_REPLAY_WINDOW_SIZE
    } else {
        window_size
    };
    let time_window = if time_window.is_zero() {
        DEFAULT_REPLAY_WINDOW_TIME
    } else {
        time_window
    };
    (window_size, time_window)
}

pub struct ReplayWindow {
    window_size: u32,
    initialized: bool,
    highest_id: u32,
    highest_timestamp: u32,
    bitmap: Vec<u64>,
    arrival_times: Vec<Option<Instant>>,
    minimum_id: u32,
    time_window: Duration,
}

impl ReplayWindow {
    /// Upstream `--replay-window 0` accepts only strictly monotonic IDs.
    pub fn new(window_size: u32, time_window: Duration) -> Self {
        let word_count = (window_size as u64).div_ceil(64) as usize;
        Self {
            window_size,
            initialized: false,
            highest_id: 0,
            highest_timestamp: 0,
            bitmap: vec![0; word_count],
            arrival_times: vec![None; window_size as usize],
            minimum_id: 0,
            time_window,
        }
    }

    /// Upstream `packet_id_test` long form: timestamp backtracking is
    /// rejected and the sequence window resets when the timestamp advances.
    pub fn accept_long_form(&mut self, packet_id: u32, timestamp: u32) -> bool {
        if packet_id == 0 {
            return false;
        }
        if !self.initialized {
            if self.window_size == 0 && timestamp > 0 && packet_id != 1 {
                return false;
            }
            self.initialize(packet_id, timestamp);
            return true;
        }
        if timestamp < self.highest_timestamp {
            return false;
        }
        if timestamp > self.highest_timestamp {
            if self.window_size == 0 && packet_id != 1 {
                return false;
            }
            self.initialize(packet_id, timestamp);
            return true;
        }
        self.accept_locked(packet_id)
    }

    fn accept_locked(&mut self, packet_id: u32) -> bool {
        if !self.initialized {
            self.initialize(packet_id, 0);
            return true;
        }
        if self.window_size == 0 {
            if packet_id != self.highest_id.wrapping_add(1) {
                return false;
            }
            self.highest_id = packet_id;
            return true;
        }
        self.reap();
        if packet_id > self.highest_id {
            let shift = packet_id - self.highest_id;
            if shift >= self.window_size {
                self.bitmap.fill(0);
                self.arrival_times.fill(None);
            } else {
                shift_bitmap(&mut self.bitmap, shift);
                shift_times(&mut self.arrival_times, shift);
            }
            self.bitmap[0] |= 1;
            self.arrival_times[0] = Some(Instant::now());
            self.highest_id = packet_id;
            return true;
        }
        if packet_id < self.minimum_id {
            return false;
        }
        let offset = self.highest_id - packet_id;
        if offset >= self.window_size {
            return false;
        }
        let word_index = (offset / 64) as usize;
        let bit_index = offset % 64;
        let packet_mask = 1u64 << bit_index;
        if self.bitmap[word_index] & packet_mask != 0 {
            return false;
        }
        self.bitmap[word_index] |= packet_mask;
        self.arrival_times[offset as usize] = Some(Instant::now());
        true
    }

    fn initialize(&mut self, packet_id: u32, timestamp: u32) {
        self.initialized = true;
        self.highest_timestamp = timestamp;
        self.highest_id = packet_id;
        self.minimum_id = 0;
        self.bitmap.fill(0);
        self.arrival_times.fill(None);
        if self.window_size > 0 {
            self.bitmap[0] = 1;
            self.arrival_times[0] = Some(Instant::now());
        }
    }

    fn reap(&mut self) {
        if self.time_window.is_zero() {
            return;
        }
        let cutoff = Instant::now() - self.time_window;
        for (offset, arrival_time) in self.arrival_times.iter().enumerate() {
            let Some(arrival_time) = arrival_time else {
                continue;
            };
            if *arrival_time >= cutoff {
                continue;
            }
            let minimum_id = self.highest_id.wrapping_sub(offset as u32).wrapping_add(1);
            if minimum_id > self.minimum_id {
                self.minimum_id = minimum_id;
            }
            return;
        }
    }
}

fn shift_bitmap(bitmap: &mut [u64], shift: u32) {
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let word_count = bitmap.len();
    for target_index in (0..word_count).rev() {
        let source_index = target_index as isize - word_shift as isize;
        let result = if source_index >= 0 {
            let source = source_index as usize;
            let mut result = bitmap[source] << bit_shift;
            if bit_shift > 0 && source >= 1 {
                result |= bitmap[source - 1] >> (64 - bit_shift);
            }
            result
        } else {
            0
        };
        bitmap[target_index] = result;
    }
}

fn shift_times(arrival_times: &mut [Option<Instant>], shift: u32) {
    if shift == 0 || arrival_times.is_empty() {
        return;
    }
    if shift as usize >= arrival_times.len() {
        for slot in arrival_times.iter_mut() {
            *slot = None;
        }
        return;
    }
    let shift = shift as usize;
    arrival_times.copy_within(..arrival_times.len() - shift, shift);
    for slot in arrival_times.iter_mut().take(shift) {
        *slot = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_size_zero_requires_strict_monotonic_ids() {
        let mut w = ReplayWindow::new(0, Duration::ZERO);
        assert!(w.accept_long_form(1, 0));
        assert!(!w.accept_long_form(1, 0)); // duplicate
        assert!(w.accept_long_form(2, 0));
        assert!(!w.accept_long_form(4, 0)); // gap
        assert!(w.accept_long_form(3, 0));
    }

    #[test]
    fn window_rejects_duplicates_and_old_ids() {
        let mut w = ReplayWindow::new(64, Duration::ZERO);
        assert!(w.accept_long_form(10, 0));
        assert!(!w.accept_long_form(10, 0));
        assert!(w.accept_long_form(11, 0));
        assert!(w.accept_long_form(9, 0));
        assert!(!w.accept_long_form(9, 0));
        assert!(w.accept_long_form(100, 0)); // jump clears the window
        assert!(!w.accept_long_form(9, 0)); // flushed (below window)
        assert!(!w.accept_long_form(1, 0)); // flushed (below window)
    }

    #[test]
    fn window_shifts_when_advanced_far() {
        let mut w = ReplayWindow::new(64, Duration::ZERO);
        assert!(w.accept_long_form(1, 0));
        assert!(w.accept_long_form(1000, 0));
        assert!(!w.accept_long_form(1, 0)); // flushed
        assert!(w.accept_long_form(999, 0));
        assert!(!w.accept_long_form(999, 0));
    }

    #[test]
    fn timestamp_backtracking_rejected_and_advance_resets() {
        let mut w = ReplayWindow::new(64, Duration::ZERO);
        assert!(w.accept_long_form(1, 100));
        assert!(w.accept_long_form(2, 100));
        assert!(!w.accept_long_form(3, 99)); // backtracking
        assert!(w.accept_long_form(1, 101)); // timestamp advance resets window
        assert!(!w.accept_long_form(1, 101));
    }

    #[test]
    fn window_zero_strict_with_timestamps() {
        let mut w = ReplayWindow::new(0, Duration::ZERO);
        assert!(!w.accept_long_form(5, 10)); // first packet must be id 1
        assert!(w.accept_long_form(1, 10));
        assert!(w.accept_long_form(2, 10));
        assert!(w.accept_long_form(1, 11)); // timestamp advance resets
        assert!(!w.accept_long_form(3, 11));
    }

    #[test]
    fn parameters_defaults() {
        assert_eq!(
            replay_window_parameters(0, Duration::ZERO),
            (DEFAULT_REPLAY_WINDOW_SIZE, DEFAULT_REPLAY_WINDOW_TIME)
        );
        assert_eq!(
            replay_window_parameters(128, Duration::from_secs(30)),
            (128, Duration::from_secs(30))
        );
    }
}
