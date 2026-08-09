//! Abuse controls for the doors a stranger can knock on.
//!
//! Almost everything on this server is guarded by a 244-bit secret, which is
//! not worth guessing. Two things are. An enrollment code is short because a
//! person reads it aloud and types it, and the bearer-token check is reachable
//! by anyone who can open a socket. Both are throttled here.
//!
//! Two shapes of control live in this module because they answer different
//! questions. A [`RateLimiter`] caps how fast anyone may knock, including
//! callers who are doing nothing wrong; it recovers continuously, so the worst
//! it does to a legitimate client is make it wait. A [`Backoff`] punishes only
//! repeated *failure*, and grows the wait each time, which is what makes
//! guessing pointless rather than merely slow.
//!
//! State is in-process and bounded. A restart forgets it, so this is an abuse
//! control rather than a durable lockout — the durable defence remains that a
//! code is high-entropy, single-use, and expires in minutes.

use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Upper bound on tracked keys, so an attacker rotating source addresses cannot
/// turn the limiter itself into unbounded memory growth.
const MAX_TRACKED_KEYS: usize = 50_000;

/// How much traffic one key is allowed: `burst` requests up front, then one
/// more every `interval`.
#[derive(Clone, Copy, Debug)]
pub struct Quota {
    burst: u32,
    interval: Duration,
}

impl Quota {
    pub fn per_minute(rate: u32) -> Self {
        let rate = rate.max(1);

        Self {
            burst: rate,
            interval: Duration::from_secs(60) / rate,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: u32,
    /// When the tokens on hand were last accounted for. Advanced by whole
    /// intervals rather than to the current instant, so a caller checking more
    /// often than the refill rate does not lose partial progress each time.
    updated: Instant,
}

/// A token bucket per key.
#[derive(Debug)]
pub struct RateLimiter {
    quota: Quota,
    state: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(quota: Quota) -> Self {
        Self {
            quota,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Spends one token for `key`, or reports how long the caller must wait.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut state = self.lock();

        if !state.contains_key(key) {
            let full_in = self.quota.interval.saturating_mul(self.quota.burst);
            make_room(&mut state, |bucket| {
                now.saturating_duration_since(bucket.updated) >= full_in
            });
        }

        let bucket = state.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.quota.burst,
            updated: now,
        });

        self.refill(bucket, now);

        if bucket.tokens == 0 {
            let waited = now.saturating_duration_since(bucket.updated);
            return Err(self.quota.interval.saturating_sub(waited).max(MINIMUM_WAIT));
        }

        bucket.tokens -= 1;
        Ok(())
    }

    fn refill(&self, bucket: &mut Bucket, now: Instant) {
        let elapsed = now.saturating_duration_since(bucket.updated);
        let gained = elapsed.as_nanos() / self.quota.interval.as_nanos().max(1);

        if gained == 0 {
            return;
        }

        if gained >= u128::from(self.quota.burst) {
            bucket.tokens = self.quota.burst;
            bucket.updated = now;
            return;
        }

        let gained = gained as u32;
        bucket.tokens = bucket.tokens.saturating_add(gained).min(self.quota.burst);
        bucket.updated += self.quota.interval * gained;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Bucket>> {
        self.state.lock().unwrap_or_else(|poisoned| {
            // A limiter holds no invariant a panic could have broken, and
            // refusing to serve because one request paniced would hand an
            // attacker a denial of service.
            self.state.clear_poison();
            poisoned.into_inner()
        })
    }
}

#[derive(Debug)]
struct Failures {
    count: u32,
    /// Also doubles as the last-touched stamp: it is set to the current instant
    /// on every failure, whether or not that failure earned a lockout.
    locked_until: Instant,
}

/// A lockout per key that doubles with each consecutive failure.
#[derive(Debug)]
pub struct Backoff {
    /// Consecutive failures allowed before lockouts begin, so an ordinary
    /// fat-fingered code costs nothing.
    threshold: u32,
    base: Duration,
    max: Duration,
    state: Mutex<HashMap<String, Failures>>,
}

impl Backoff {
    pub fn new(threshold: u32, base: Duration, max: Duration) -> Self {
        Self {
            threshold: threshold.max(1),
            base,
            max,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Reports how long `key` is still locked out for, if it is.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let state = self.lock();

        match state.get(key) {
            Some(failures) if failures.locked_until > now => {
                Err(failures.locked_until.saturating_duration_since(now))
            }
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now());
    }

    fn record_failure_at(&self, key: &str, now: Instant) {
        let mut state = self.lock();

        if !state.contains_key(key) {
            let max = self.max;
            make_room(&mut state, |failures| {
                now.saturating_duration_since(failures.locked_until) >= max
            });
        }

        let failures = state.entry(key.to_owned()).or_insert(Failures {
            count: 0,
            locked_until: now,
        });

        failures.count = failures.count.saturating_add(1);
        failures.locked_until = now + self.lockout(failures.count);
    }

    /// Forgets a key's history. Called on success, so a client that is simply
    /// slow to find the right code is not punished for the rest of the day.
    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    fn lockout(&self, count: u32) -> Duration {
        let Some(over) = count.checked_sub(self.threshold) else {
            return Duration::ZERO;
        };

        self.base
            .checked_mul(2_u32.saturating_pow(over.min(31)))
            .unwrap_or(self.max)
            .min(self.max)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Failures>> {
        self.state.lock().unwrap_or_else(|poisoned| {
            self.state.clear_poison();
            poisoned.into_inner()
        })
    }
}

/// Never report a wait of zero: a caller told to retry immediately would
/// simply spin.
const MINIMUM_WAIT: Duration = Duration::from_millis(1);

/// Keeps a tracking map bounded before a new key is inserted.
fn make_room<K: Clone + Eq + Hash, V>(state: &mut HashMap<K, V>, is_stale: impl Fn(&V) -> bool) {
    if state.len() < MAX_TRACKED_KEYS {
        return;
    }

    state.retain(|_, value| !is_stale(value));

    if state.len() < MAX_TRACKED_KEYS {
        return;
    }

    // Every tracked key is still live, so the map is at its cap under real
    // load. Evict a batch rather than one entry at a time: the scan above is
    // linear, and paying for it on every single insert would itself be the
    // denial of service. Forgetting a key costs at most one extra burst,
    // whereas refusing to track new keys would let an attacker fill the map
    // and then walk in unthrottled.
    let doomed: Vec<K> = state
        .keys()
        .take((MAX_TRACKED_KEYS / 16).max(1))
        .cloned()
        .collect();

    for key in doomed {
        state.remove(&key);
    }
}

/// Collapses an address to the unit that costs something to rent.
///
/// A single IPv4 address is that unit. An IPv6 host is normally handed a whole
/// /64, so keying on the full address would let one machine present a
/// practically unlimited supply of "clients".
pub fn client_key(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let mut prefix = [0_u8; 16];
            prefix[..8].copy_from_slice(&address.octets()[..8]);

            format!("{}/64", Ipv6Addr::from(prefix))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_and_then_refills() {
        let limiter = RateLimiter::new(Quota::per_minute(6));
        let start = Instant::now();

        for _ in 0..6 {
            assert!(limiter.check_at("client", start).is_ok());
        }

        let wait = limiter
            .check_at("client", start)
            .expect_err("the burst is spent");
        assert!(wait <= Duration::from_secs(10) && wait > Duration::ZERO);

        // One token every ten seconds, and no more than one.
        assert!(
            limiter
                .check_at("client", start + Duration::from_secs(10))
                .is_ok()
        );
        assert!(
            limiter
                .check_at("client", start + Duration::from_secs(10))
                .is_err()
        );

        // Idling longer than the whole bucket restores it, but not beyond.
        assert!(
            limiter
                .check_at("client", start + Duration::from_secs(600))
                .is_ok()
        );
    }

    #[test]
    fn partial_progress_toward_a_token_is_not_discarded() {
        let limiter = RateLimiter::new(Quota::per_minute(6));
        let start = Instant::now();

        assert!(limiter.check_at("client", start).is_ok());

        // Checking more often than the refill rate must not keep resetting the
        // clock, or a busy client would never earn another token.
        for tick in 1..=9 {
            let _ = limiter.check_at("client", start + Duration::from_secs(tick));
        }

        assert!(
            limiter
                .check_at("client", start + Duration::from_secs(10))
                .is_ok()
        );
    }

    #[test]
    fn one_key_does_not_spend_anothers_tokens() {
        let limiter = RateLimiter::new(Quota::per_minute(1));
        let start = Instant::now();

        assert!(limiter.check_at("first", start).is_ok());
        assert!(limiter.check_at("first", start).is_err());
        assert!(limiter.check_at("second", start).is_ok());
    }

    #[test]
    fn lockouts_start_after_the_threshold_and_then_double() {
        let backoff = Backoff::new(3, Duration::from_secs(1), Duration::from_secs(60));
        let start = Instant::now();

        for _ in 0..2 {
            backoff.record_failure_at("client", start);
            assert!(backoff.check_at("client", start).is_ok());
        }

        backoff.record_failure_at("client", start);
        assert_eq!(
            backoff.check_at("client", start),
            Err(Duration::from_secs(1))
        );

        backoff.record_failure_at("client", start);
        assert_eq!(
            backoff.check_at("client", start),
            Err(Duration::from_secs(2))
        );

        backoff.record_failure_at("client", start);
        assert_eq!(
            backoff.check_at("client", start),
            Err(Duration::from_secs(4))
        );

        // The wait shrinks as it is served, and clears when it is over.
        assert_eq!(
            backoff.check_at("client", start + Duration::from_secs(3)),
            Err(Duration::from_secs(1))
        );
        assert!(
            backoff
                .check_at("client", start + Duration::from_secs(4))
                .is_ok()
        );
    }

    #[test]
    fn a_lockout_is_capped() {
        let backoff = Backoff::new(1, Duration::from_secs(1), Duration::from_secs(10));
        let start = Instant::now();

        for _ in 0..64 {
            backoff.record_failure_at("client", start);
        }

        assert_eq!(
            backoff.check_at("client", start),
            Err(Duration::from_secs(10))
        );
    }

    #[test]
    fn success_forgets_the_failures_before_it() {
        let backoff = Backoff::new(1, Duration::from_secs(1), Duration::from_secs(60));
        let start = Instant::now();

        backoff.record_failure_at("client", start);
        backoff.record_failure_at("client", start);
        backoff.record_success("client");

        assert!(backoff.check_at("client", start).is_ok());

        // And the count restarts, rather than resuming where it left off.
        backoff.record_failure_at("client", start);
        assert_eq!(
            backoff.check_at("client", start),
            Err(Duration::from_secs(1))
        );
    }

    #[test]
    fn tracking_maps_stay_bounded() {
        let limiter = RateLimiter::new(Quota::per_minute(1));
        let start = Instant::now();

        for index in 0..MAX_TRACKED_KEYS + 100 {
            let _ = limiter.check_at(&format!("client-{index}"), start);
        }

        assert!(limiter.lock().len() <= MAX_TRACKED_KEYS);
    }

    #[test]
    fn an_ipv6_host_is_keyed_by_its_prefix() {
        let first: IpAddr = "2001:db8:1234:5678:1::1".parse().expect("address");
        let second: IpAddr = "2001:db8:1234:5678:ffff::abcd".parse().expect("address");
        let other: IpAddr = "2001:db8:1234:9999::1".parse().expect("address");

        assert_eq!(client_key(first), client_key(second));
        assert_ne!(client_key(first), client_key(other));

        let v4: IpAddr = "203.0.113.7".parse().expect("address");
        assert_eq!(client_key(v4), "203.0.113.7");
    }
}
