//! Hysteria-style bandwidth controller: explicit pacing, RTT-sized window and
//! bounded loss compensation. Based on apernet/hysteria's Brutal algorithm
//! (MIT), implemented for Quinn's controller callbacks. Rates here are bytes/s;
//! only ControllerMetrics uses bits/s.

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct BrutalConfig {
    bytes_per_second: u64,
}

impl BrutalConfig {
    pub(super) fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second: bytes_per_second.max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    second: Option<u64>,
    acked: u64,
    lost: u64,
}

#[derive(Debug, Clone)]
struct Brutal {
    config: Arc<BrutalConfig>,
    epoch: Instant,
    mtu: u64,
    rtt: Duration,
    samples: [Sample; 5],
    ack_rate: f64,
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal {
            config: self,
            epoch: now,
            mtu: u64::from(current_mtu),
            rtt: Duration::from_millis(50),
            samples: [Sample::default(); 5],
            ack_rate: 1.0,
        })
    }
}

impl Brutal {
    fn sample(&mut self, now: Instant, acked: u64, lost: u64) {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let slot = &mut self.samples[(second % 5) as usize];
        if slot.second != Some(second) {
            *slot = Sample {
                second: Some(second),
                ..Sample::default()
            };
        }
        slot.acked = slot.acked.saturating_add(acked);
        slot.lost = slot.lost.saturating_add(lost);
        let (acks, losses) = self
            .samples
            .iter()
            .filter(|s| s.second.is_some_and(|t| second.saturating_sub(t) < 5))
            .fold((0u64, 0u64), |(a, l), s| {
                (a.saturating_add(s.acked), l.saturating_add(s.lost))
            });
        let total = acks.saturating_add(losses);
        self.ack_rate = if total < 50 {
            1.0
        } else {
            (acks as f64 / total as f64).max(0.8)
        };
    }

    fn byte_rate(&self) -> u64 {
        (self.config.bytes_per_second as f64 / self.ack_rate) as u64
    }
}

impl Controller for Brutal {
    fn on_sent(&mut self, now: Instant, _bytes: u64, _packet: u64) {
        // Expire compensation after an idle period, before the next ACK.
        self.sample(now, 0, 0);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get();
        self.sample(now, 1, 0);
    }

    fn on_packet_lost(&mut self, now: Instant) {
        self.sample(now, 0, 1);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _persistent: bool,
        _bytes: u64,
    ) {
        // No multiplicative backoff. Loss samples are reported per packet,
        // independently of batching and ECN congestion notifications.
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = u64::from(mtu);
    }
    fn pacing_rate_bytes(&self) -> Option<u64> {
        Some(self.byte_rate())
    }
    fn window(&self) -> u64 {
        ((self.byte_rate() as f64 * self.rtt.as_secs_f64() * 2.0) as u64).max(self.mtu)
    }
    fn initial_window(&self) -> u64 {
        self.window()
    }
    fn metrics(&self) -> ControllerMetrics {
        let mut result = ControllerMetrics::default();
        result.congestion_window = self.window();
        result.pacing_rate = Some(self.byte_rate().saturating_mul(8));
        result
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn controller() -> Brutal {
        Brutal {
            config: Arc::new(BrutalConfig::new(12_500_000)),
            epoch: Instant::now(),
            mtu: 1200,
            rtt: Duration::from_millis(50),
            samples: [Sample::default(); 5],
            ack_rate: 1.0,
        }
    }
    #[test]
    fn bandwidth_units_and_rtt_window() {
        let mut c = controller();
        assert_eq!(c.pacing_rate_bytes(), Some(12_500_000));
        assert_eq!(c.metrics().pacing_rate, Some(100_000_000));
        for (ms, window) in [(10, 250_000), (50, 1_250_000), (200, 5_000_000)] {
            c.rtt = Duration::from_millis(ms);
            assert_eq!(c.window(), window);
        }
    }
    #[test]
    fn loss_compensation_is_sampled_bounded_and_expires() {
        let mut c = controller();
        let now = c.epoch;
        for _ in 0..45 {
            c.sample(now, 1, 0);
        }
        for _ in 0..5 {
            c.on_packet_lost(now);
        }
        assert!((c.byte_rate() as f64 / 12_500_000.0 - 1.0 / 0.9).abs() < 0.00001);
        for _ in 0..100 {
            c.on_packet_lost(now);
        }
        assert_eq!(c.byte_rate(), 15_625_000);
        c.on_sent(now + Duration::from_secs(5), 1200, 1);
        assert_eq!(c.byte_rate(), 12_500_000);
    }
    #[test]
    fn undersampled_loss_and_ecn_do_not_change_rate() {
        let mut c = controller();
        let now = c.epoch;
        for _ in 0..49 {
            c.on_packet_lost(now);
        }
        c.on_congestion_event(now, now, true, 0);
        assert_eq!(c.byte_rate(), 12_500_000);
        c.on_mtu_update(9000);
        c.rtt = Duration::ZERO;
        assert_eq!(c.window(), 9000);
    }
}
