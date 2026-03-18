use std::time::Duration;
use tokio::time::sleep;
use tracing;

use crate::error::ProxyError;

/// Retry configuration for a specific operation type.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_backoff: Duration,
    pub retryable_status_codes: Vec<u16>,
}

impl RetryPolicy {
    /// Create retry policy for read operations (GET/HEAD/LIST).
    /// Reads are always safe to retry on transient errors.
    pub fn for_reads(max_attempts: u32, base_backoff_ms: u64) -> Self {
        Self {
            max_attempts,
            base_backoff: Duration::from_millis(base_backoff_ms),
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
        }
    }

    /// Create retry policy for idempotent writes (DELETE).
    /// Idempotent writes are safe to retry since repeating them has the same effect.
    pub fn for_idempotent_writes(max_attempts: u32, base_backoff_ms: u64) -> Self {
        Self {
            max_attempts,
            base_backoff: Duration::from_millis(base_backoff_ms),
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
        }
    }

    /// Create retry policy for non-idempotent writes (PUT).
    /// Non-idempotent writes get limited retries since they may have side effects.
    pub fn for_writes(max_attempts: u32, base_backoff_ms: u64) -> Self {
        Self {
            max_attempts,
            base_backoff: Duration::from_millis(base_backoff_ms),
            // Only retry on errors that clearly indicate the request was not processed.
            retryable_status_codes: vec![408, 429, 503],
        }
    }

    /// No retries — execute exactly once.
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            base_backoff: Duration::from_millis(0),
            retryable_status_codes: vec![],
        }
    }
}

/// Check if a ProxyError is retryable.
///
/// Backend/network errors and timeouts are retryable.
/// Auth errors, invalid requests, and unsupported operations are not.
pub fn is_retryable(err: &ProxyError) -> bool {
    matches!(err, ProxyError::Backend { .. } | ProxyError::Timeout { .. })
}

/// Calculate backoff duration for a given attempt using exponential backoff.
/// attempt is 0-indexed (0 = first retry, 1 = second retry, etc.).
fn backoff_duration(base: Duration, attempt: u32) -> Duration {
    // Exponential backoff: base * 2^attempt
    // Cap the exponent to avoid overflow.
    let exp = attempt.min(10);
    base.saturating_mul(1u32 << exp)
}

/// Execute an operation with retries according to the given policy.
/// The operation closure receives the attempt number (1-indexed).
pub async fn with_retry<F, Fut, T>(
    policy: &RetryPolicy,
    operation_name: &str,
    f: F,
) -> Result<T, ProxyError>
where
    F: Fn(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, ProxyError>>,
{
    let max = policy.max_attempts.max(1);
    let mut last_err: Option<ProxyError> = None;

    for attempt in 1..=max {
        match f(attempt).await {
            Ok(result) => return Ok(result),
            Err(err) => {
                let retryable = is_retryable(&err);
                let attempts_remaining = max - attempt;

                if !retryable || attempts_remaining == 0 {
                    if attempt > 1 {
                        tracing::warn!(
                            operation = operation_name,
                            attempt,
                            max_attempts = max,
                            error = %err,
                            "all retry attempts exhausted"
                        );
                    }
                    return Err(err);
                }

                let delay = backoff_duration(policy.base_backoff, attempt - 1);
                tracing::warn!(
                    operation = operation_name,
                    attempt,
                    max_attempts = max,
                    error = %err,
                    retry_after_ms = delay.as_millis() as u64,
                    "retryable error, backing off"
                );

                last_err = Some(err);
                sleep(delay).await;
            }
        }
    }

    // This should be unreachable, but return the last error just in case.
    Err(last_err.unwrap_or_else(|| ProxyError::Internal {
        source: "retry loop completed without result".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_policy_for_reads_has_correct_status_codes() {
        let policy = RetryPolicy::for_reads(3, 100);
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.base_backoff, Duration::from_millis(100));
        assert_eq!(policy.retryable_status_codes, vec![408, 429, 500, 502, 503, 504]);
    }

    #[test]
    fn test_retry_policy_for_idempotent_writes() {
        let policy = RetryPolicy::for_idempotent_writes(2, 200);
        assert_eq!(policy.max_attempts, 2);
        assert_eq!(policy.retryable_status_codes, vec![408, 429, 500, 502, 503, 504]);
    }

    #[test]
    fn test_retry_policy_for_writes() {
        let policy = RetryPolicy::for_writes(1, 50);
        assert_eq!(policy.max_attempts, 1);
        assert_eq!(policy.retryable_status_codes, vec![408, 429, 503]);
    }

    #[test]
    fn test_retry_policy_no_retry() {
        let policy = RetryPolicy::no_retry();
        assert_eq!(policy.max_attempts, 1);
        assert!(policy.retryable_status_codes.is_empty());
    }

    #[test]
    fn test_is_retryable_backend_error() {
        let err = ProxyError::Backend {
            source: "connection reset".into(),
            operation: "get_object".into(),
        };
        assert!(is_retryable(&err));
    }

    #[test]
    fn test_is_retryable_timeout() {
        let err = ProxyError::Timeout {
            operation: "get_object".into(),
        };
        assert!(is_retryable(&err));
    }

    #[test]
    fn test_is_not_retryable_auth() {
        let err = ProxyError::Auth {
            message: "forbidden".into(),
        };
        assert!(!is_retryable(&err));
    }

    #[test]
    fn test_is_not_retryable_invalid_request() {
        let err = ProxyError::InvalidRequest {
            message: "bad key".into(),
        };
        assert!(!is_retryable(&err));
    }

    #[tokio::test]
    async fn test_with_retry_succeeds_immediately() {
        let policy = RetryPolicy::for_reads(3, 10);
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let result = with_retry(&policy, "test_op", |_attempt| {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ProxyError>(42)
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_with_retry_retries_then_succeeds() {
        let policy = RetryPolicy::for_reads(3, 10);
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let result = with_retry(&policy, "test_op", |_attempt| {
            let attempts = attempts_clone.clone();
            async move {
                let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(ProxyError::Backend {
                        source: "transient error".into(),
                        operation: "test_op".into(),
                    })
                } else {
                    Ok::<_, ProxyError>(99)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_gives_up_after_max_attempts() {
        let policy = RetryPolicy::for_reads(3, 10);
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let result = with_retry(&policy, "test_op", |_attempt| {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(ProxyError::Backend {
                    source: "persistent error".into(),
                    operation: "test_op".into(),
                })
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_does_not_retry_non_retryable() {
        let policy = RetryPolicy::for_reads(3, 10);
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let result = with_retry(&policy, "test_op", |_attempt| {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(ProxyError::Auth {
                    message: "access denied".into(),
                })
            }
        })
        .await;

        assert!(result.is_err());
        // Should have given up after the first attempt since Auth is not retryable.
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_backoff_increases_between_attempts() {
        let base = Duration::from_millis(100);
        let d0 = backoff_duration(base, 0);
        let d1 = backoff_duration(base, 1);
        let d2 = backoff_duration(base, 2);

        assert_eq!(d0, Duration::from_millis(100)); // 100 * 2^0
        assert_eq!(d1, Duration::from_millis(200)); // 100 * 2^1
        assert_eq!(d2, Duration::from_millis(400)); // 100 * 2^2
        assert!(d0 < d1);
        assert!(d1 < d2);
    }

    #[test]
    fn test_backoff_caps_exponent() {
        let base = Duration::from_millis(100);
        // Very high attempt number should not overflow.
        let d = backoff_duration(base, 100);
        let d_capped = backoff_duration(base, 10);
        assert_eq!(d, d_capped);
    }

    #[tokio::test]
    async fn test_with_retry_no_retry_policy() {
        let policy = RetryPolicy::no_retry();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let result = with_retry(&policy, "test_op", |_attempt| {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(ProxyError::Backend {
                    source: "error".into(),
                    operation: "test_op".into(),
                })
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
