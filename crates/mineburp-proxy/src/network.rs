//! Simulated network conditions applied where bytes leave the proxy.
//!
//! The proxy terminates TCP on both sides, so loss and reordering are not
//! meaningful here: the stream underneath is reliable and ordered. What can be
//! shaped is *when* each frame leaves — a fixed delay, random jitter, and a
//! bandwidth ceiling — which is enough to exercise timeouts, lag compensation,
//! movement prediction, and keep-alive handling in a client or server.

use rsa::rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{Duration, Instant};

/// The longest delay or jitter that can be configured. Longer than every
/// vanilla timeout, short enough that a typo cannot park a session for hours.
pub const MAX_LINK_DELAY_MS: u32 = 120_000;

/// Shaping for one direction of every proxied connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LinkConditions {
    /// Added to every frame, measured from when the proxy received it.
    pub delay_ms: u32,
    /// A uniformly random extra delay in `0..=jitter_ms`. Frames still leave in
    /// order, because the stream they travel on is ordered.
    pub jitter_ms: u32,
    /// Bytes per second this direction may carry; `None` is unlimited.
    pub bandwidth_bytes_per_second: Option<u64>,
}

impl LinkConditions {
    /// Whether these conditions leave traffic untouched.
    #[must_use]
    pub const fn is_neutral(&self) -> bool {
        self.delay_ms == 0 && self.jitter_ms == 0 && self.bandwidth_bytes_per_second.is_none()
    }
}

/// Shaping for both directions. `client_to_server` applies to bytes written to
/// the server, `server_to_client` to bytes written to the game client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConditions {
    pub client_to_server: LinkConditions,
    pub server_to_client: LinkConditions,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkConditionsError {
    #[error("delay and jitter must each be at most {MAX_LINK_DELAY_MS} ms")]
    DelayTooLong,
    #[error("a bandwidth limit must be at least one byte per second")]
    ZeroBandwidth,
}

impl NetworkConditions {
    pub fn validate(&self) -> Result<(), NetworkConditionsError> {
        for link in [self.client_to_server, self.server_to_client] {
            if link.delay_ms > MAX_LINK_DELAY_MS || link.jitter_ms > MAX_LINK_DELAY_MS {
                return Err(NetworkConditionsError::DelayTooLong);
            }
            if link.bandwidth_bytes_per_second == Some(0) {
                return Err(NetworkConditionsError::ZeroBandwidth);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn for_direction(&self, direction: mineburp_core::Direction) -> LinkConditions {
        match direction {
            mineburp_core::Direction::ClientToServer => self.client_to_server,
            mineburp_core::Direction::ServerToClient => self.server_to_client,
        }
    }
}

/// Per-writer state that turns [`LinkConditions`] into release times.
#[derive(Debug)]
pub(crate) struct Shaper {
    /// Nothing may leave before the previous frame: the stream is ordered.
    last_release: Option<Instant>,
    /// When the bandwidth budget next allows a byte out.
    next_free: Option<Instant>,
    random: u64,
}

impl Default for Shaper {
    fn default() -> Self {
        Self {
            last_release: None,
            next_free: None,
            // xorshift must not start at zero.
            random: OsRng.next_u64() | 1,
        }
    }
}

impl Shaper {
    /// When a frame of `length` bytes queued at `queued_at` may be written.
    pub(crate) fn release_at(
        &mut self,
        link: &LinkConditions,
        queued_at: Instant,
        now: Instant,
    ) -> Instant {
        let jitter = if link.jitter_ms == 0 {
            0
        } else {
            self.next_random() % (u64::from(link.jitter_ms) + 1)
        };
        let mut release = queued_at
            + Duration::from_millis(u64::from(link.delay_ms))
            + Duration::from_millis(jitter);
        if let Some(last) = self.last_release {
            release = release.max(last);
        }
        if link.bandwidth_bytes_per_second.is_some()
            && let Some(free) = self.next_free
        {
            release = release.max(free);
        }
        release.max(now)
    }

    /// Records that `length` bytes left at `sent_at`.
    pub(crate) fn sent(&mut self, link: &LinkConditions, sent_at: Instant, length: usize) {
        self.last_release = Some(sent_at);
        self.next_free = link.bandwidth_bytes_per_second.map(|rate| {
            #[allow(clippy::cast_precision_loss)]
            let seconds = length as f64 / rate as f64;
            let start = self.next_free.map_or(sent_at, |free| free.max(sent_at));
            start + Duration::from_secs_f64(seconds)
        });
    }

    fn next_random(&mut self) -> u64 {
        let mut value = self.random;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.random = value;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_unusable_settings() {
        let mut conditions = NetworkConditions::default();
        assert!(conditions.validate().is_ok());
        conditions.server_to_client.delay_ms = MAX_LINK_DELAY_MS + 1;
        assert_eq!(
            conditions.validate(),
            Err(NetworkConditionsError::DelayTooLong)
        );
        conditions.server_to_client.delay_ms = 0;
        conditions.client_to_server.bandwidth_bytes_per_second = Some(0);
        assert_eq!(
            conditions.validate(),
            Err(NetworkConditionsError::ZeroBandwidth)
        );
    }

    #[test]
    fn delay_is_measured_from_arrival_and_never_reorders() {
        let mut shaper = Shaper::default();
        let link = LinkConditions {
            delay_ms: 100,
            jitter_ms: 50,
            bandwidth_bytes_per_second: None,
        };
        let start = Instant::now();
        let mut previous = start;
        for index in 0..200 {
            let queued = start + Duration::from_millis(index);
            let release = shaper.release_at(&link, queued, start);
            assert!(release >= queued + Duration::from_millis(100));
            assert!(release <= queued + Duration::from_millis(150) || release == previous);
            assert!(release >= previous, "frames must leave in order");
            shaper.sent(&link, release, 10);
            previous = release;
        }
    }

    #[test]
    fn bandwidth_spaces_frames_by_their_size() {
        let mut shaper = Shaper::default();
        let link = LinkConditions {
            delay_ms: 0,
            jitter_ms: 0,
            bandwidth_bytes_per_second: Some(1_000),
        };
        let start = Instant::now();
        let first = shaper.release_at(&link, start, start);
        assert_eq!(first, start);
        shaper.sent(&link, first, 500);
        let second = shaper.release_at(&link, start, start);
        assert_eq!(second, start + Duration::from_millis(500));
    }

    #[test]
    fn neutral_conditions_release_immediately() {
        let mut shaper = Shaper::default();
        let link = LinkConditions::default();
        assert!(link.is_neutral());
        let now = Instant::now();
        assert_eq!(shaper.release_at(&link, now, now), now);
        shaper.sent(&link, now, 1 << 20);
        assert_eq!(shaper.release_at(&link, now, now), now);
    }
}
