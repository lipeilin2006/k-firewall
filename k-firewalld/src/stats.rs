use k_firewall_common::Stats;
use tracing::info;

pub fn log(s: &Stats) {
    info!(
        "packets={} passed={} dropped={} blocked={}",
        s.packets, s.passed, s.dropped, s.blocked
    );
}
