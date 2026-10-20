//! Per-IP token-bucket limiter for new relay connections.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    per_sec: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn new(per_min: u32, burst: u32) -> Self {
        Self {
            per_sec: f64::from(per_min.max(1)) / 60.0,
            burst: f64::from(burst.max(1)),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if a new connection from `ip` is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        // Opportunistic GC so the map cannot grow without bound.
        if map.len() > 50_000 {
            let full = self.burst;
            let per_sec = self.per_sec;
            map.retain(|_, (t, last)| {
                *t + now.duration_since(*last).as_secs_f64() * per_sec < full
            });
        }
        let (tokens, last) = map.entry(ip).or_insert((self.burst, now));
        *tokens =
            (*tokens + now.duration_since(*last).as_secs_f64() * self.per_sec).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_refill() {
        let rl = RateLimiter::new(60, 3);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.check_at(ip, t0));
        assert!(rl.check_at(ip, t0));
        assert!(rl.check_at(ip, t0));
        assert!(!rl.check_at(ip, t0));
        // other IPs unaffected
        assert!(rl.check_at("10.0.0.2".parse().unwrap(), t0));
        // 1 token/sec refill
        assert!(rl.check_at(ip, t0 + Duration::from_millis(1100)));
        assert!(!rl.check_at(ip, t0 + Duration::from_millis(1200)));
    }
}
