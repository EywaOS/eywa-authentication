use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    TooManyRequests,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    max_requests: u32,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }

    pub async fn check(&self, key: &str) -> Result<(), RateLimitError> {
        let mut requests = self.requests.write().await;
        let now = Instant::now();

        let entry = requests.entry(key.to_string()).or_insert_with(|| RateLimitEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) > self.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.max_requests {
            return Err(RateLimitError::TooManyRequests);
        }

        entry.count += 1;
        Ok(())
    }

    pub async fn remaining(&self, key: &str) -> u32 {
        let requests = self.requests.read().await;
        let now = Instant::now();

        if let Some(entry) = requests.get(key) {
            if now.duration_since(entry.window_start) <= self.window_duration {
                return self.max_requests.saturating_sub(entry.count);
            }
        }

        self.max_requests
    }

    pub async fn cleanup(&self) {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        requests.retain(|_, entry| now.duration_since(entry.window_start) <= self.window_duration);
    }
}
