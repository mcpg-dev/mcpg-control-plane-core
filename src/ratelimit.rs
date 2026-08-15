//! Per-IP token-bucket rate limiter for unauthenticated / public HTTP routes.
//!
//! Shared by the control-plane server and the federation OP to throttle their
//! abuse-prone public surface (enrollment, password login, token exchange,
//! signup). Deliberately small and dependency-free: a `Mutex<HashMap>` keyed by
//! client IP, refilled lazily on access. These paths are low-rate, so lock
//! contention is a non-issue and a `DashMap` / external limiter crate would be
//! overkill.
//!
//! Pure (no `axum`): callers pass the already-extracted `X-Forwarded-For` value
//! and transport peer to [`RateLimiter::client_ip`], and apply the verdict in
//! their own middleware. Keeps this crate axum-free while giving both services
//! one tested implementation.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Stop tracking idle buckets once the map grows past this, to bound memory
/// under a spray of distinct source IPs. Evicts buckets idle longer than
/// [`IDLE_EVICT`]; active attackers stay tracked (that's the point).
const MAX_TRACKED_IPS: usize = 100_000;
const IDLE_EVICT: Duration = Duration::from_secs(600);

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A lazily-refilled token bucket per client IP.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Burst capacity (max tokens).
    capacity: f64,
    /// Tokens added per second.
    refill_per_sec: f64,
    /// Honour `X-Forwarded-For` for the client IP (set only when a trusted
    /// reverse proxy / edge fronts the service, else it's spoofable).
    trust_proxy: bool,
}

impl RateLimiter {
    /// `per_min` sustained requests/IP with a `burst` allowance. `per_min == 0`
    /// disables limiting (every check passes).
    pub fn new(per_min: u32, burst: u32, trust_proxy: bool) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: burst.max(1) as f64,
            refill_per_sec: per_min as f64 / 60.0,
            trust_proxy,
        }
    }

    /// Whether limiting is active. `per_min == 0` ⇒ a no-op limiter.
    pub fn enabled(&self) -> bool {
        self.refill_per_sec > 0.0
    }

    /// Resolve the client IP: the first `X-Forwarded-For` hop when proxy trust
    /// is on, else the transport peer, else `0.0.0.0` (no `ConnectInfo` — e.g. a
    /// oneshot test; all callers then share one bucket). `xff` is the raw header
    /// value, if present.
    pub fn client_ip(&self, xff: Option<&str>, peer: Option<IpAddr>) -> IpAddr {
        if self.trust_proxy
            && let Some(xff) = xff
            && let Some(first) = xff.split(',').next()
            && let Ok(ip) = first.trim().parse::<IpAddr>()
        {
            return ip;
        }
        peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    /// Take one token for `ip`. `true` = allowed, `false` = over the limit.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// [`check`](Self::check) at an explicit instant — the seam unit tests use to
    /// exercise refill deterministically without sleeping.
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled() {
            return true;
        }
        let mut map = self.buckets.lock().unwrap();
        if map.len() > MAX_TRACKED_IPS {
            map.retain(|_, b| now.saturating_duration_since(b.last) < IDLE_EVICT);
        }
        let b = map.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn allows_burst_then_denies() {
        let rl = RateLimiter::new(60, 3, false); // 1/s sustained, burst 3
        let t = Instant::now();
        assert!(rl.check_at(ip(1), t));
        assert!(rl.check_at(ip(1), t));
        assert!(rl.check_at(ip(1), t));
        assert!(
            !rl.check_at(ip(1), t),
            "burst exhausted at the same instant"
        );
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(60, 2, false); // 1 token/sec
        let t = Instant::now();
        assert!(rl.check_at(ip(1), t));
        assert!(rl.check_at(ip(1), t));
        assert!(!rl.check_at(ip(1), t));
        assert!(rl.check_at(ip(1), t + Duration::from_secs(1)));
        assert!(!rl.check_at(ip(1), t + Duration::from_secs(1)));
    }

    #[test]
    fn buckets_are_per_ip() {
        let rl = RateLimiter::new(60, 1, false);
        let t = Instant::now();
        assert!(rl.check_at(ip(1), t));
        assert!(!rl.check_at(ip(1), t), "ip1 exhausted");
        assert!(rl.check_at(ip(2), t), "ip2 has its own bucket");
    }

    #[test]
    fn zero_per_min_disables() {
        let rl = RateLimiter::new(0, 0, false);
        assert!(!rl.enabled());
        let t = Instant::now();
        for _ in 0..1000 {
            assert!(rl.check_at(ip(1), t));
        }
    }

    #[test]
    fn xff_used_only_when_trusted() {
        let xff = Some("203.0.113.7, 10.0.0.1");
        let peer = Some(ip(9));

        let untrusted = RateLimiter::new(60, 1, false);
        assert_eq!(untrusted.client_ip(xff, peer), ip(9), "ignore XFF");

        let trusted = RateLimiter::new(60, 1, true);
        assert_eq!(
            trusted.client_ip(xff, peer),
            "203.0.113.7".parse::<IpAddr>().unwrap(),
            "first XFF hop is the real client"
        );
        // No XFF → fall back to the peer even when trusting proxies.
        assert_eq!(trusted.client_ip(None, peer), ip(9));
    }
}
