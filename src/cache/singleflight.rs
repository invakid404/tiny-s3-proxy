use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use crate::cache::key::CacheKey;

/// Result of a singleflight operation.
#[derive(Debug)]
pub enum FlightResult {
    /// This caller is the leader and should perform the fetch.
    Leader { waiter: FlightWaiter },
    /// Another caller is already fetching. Wait for the result.
    Follower { receiver: broadcast::Receiver<()> },
}

/// Handle held by the leader to notify followers when done.
pub struct FlightWaiter {
    key: CacheKey,
    sender: broadcast::Sender<()>,
    registry: Arc<Mutex<HashMap<CacheKey, broadcast::Sender<()>>>>,
}

impl std::fmt::Debug for FlightWaiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlightWaiter")
            .field("key", &self.key)
            .finish()
    }
}

impl FlightWaiter {
    /// Signal that the fill is complete. All followers will be woken.
    pub async fn complete(self) {
        let _ = self.sender.send(());
        self.registry.lock().await.remove(&self.key);
    }
}

impl Drop for FlightWaiter {
    fn drop(&mut self) {
        // When the leader drops without calling complete(), the broadcast sender
        // will be dropped, causing RecvError::Closed for followers.
        // Clean up the registry using try_lock to avoid spawning tasks
        // (which may not run if the runtime is shutting down).
        if let Ok(mut registry) = self.registry.try_lock() {
            registry.remove(&self.key);
        } else {
            // If we can't get the lock synchronously, spawn a cleanup task.
            // This is best-effort; in test shutdown scenarios it may not run.
            let registry = self.registry.clone();
            let key = self.key.clone();
            tokio::spawn(async move {
                registry.lock().await.remove(&key);
            });
        }
    }
}

/// Deduplicates concurrent requests for the same cache key.
///
/// When multiple requests miss the same key simultaneously, only the first
/// one becomes the leader (and should fetch from the backend). All others
/// become followers and wait for the leader to signal completion.
pub struct SingleFlight {
    registry: Arc<Mutex<HashMap<CacheKey, broadcast::Sender<()>>>>,
}

impl Default for SingleFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleFlight {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to acquire leadership for a given cache key.
    ///
    /// Returns `Leader` if this is the first request for this key,
    /// `Follower` if another request is already in flight.
    pub async fn try_acquire(&self, key: &CacheKey) -> FlightResult {
        let mut registry = self.registry.lock().await;
        if let Some(sender) = registry.get(key) {
            FlightResult::Follower {
                receiver: sender.subscribe(),
            }
        } else {
            let (sender, _) = broadcast::channel(1);
            registry.insert(key.clone(), sender.clone());
            FlightResult::Leader {
                waiter: FlightWaiter {
                    key: key.clone(),
                    sender,
                    registry: self.registry.clone(),
                },
            }
        }
    }

    /// Cancel an in-flight operation for a key (used when purging).
    pub async fn cancel(&self, key: &CacheKey) {
        self.registry.lock().await.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> CacheKey {
        CacheKey::new("test-bucket", "script_bundle/test.js")
    }

    #[tokio::test]
    async fn test_first_acquire_returns_leader() {
        let sf = SingleFlight::new();
        let result = sf.try_acquire(&test_key()).await;
        assert!(
            matches!(result, FlightResult::Leader { .. }),
            "first acquire should return Leader"
        );
    }

    #[tokio::test]
    async fn test_second_acquire_returns_follower() {
        let sf = SingleFlight::new();
        let key = test_key();

        let result1 = sf.try_acquire(&key).await;
        assert!(matches!(result1, FlightResult::Leader { .. }));

        let result2 = sf.try_acquire(&key).await;
        assert!(
            matches!(result2, FlightResult::Follower { .. }),
            "second acquire on same key should return Follower"
        );
    }

    #[tokio::test]
    async fn test_after_complete_new_acquire_returns_leader() {
        let sf = SingleFlight::new();
        let key = test_key();

        // First acquire: leader
        let result1 = sf.try_acquire(&key).await;
        let waiter = match result1 {
            FlightResult::Leader { waiter } => waiter,
            _ => panic!("expected Leader"),
        };

        // Complete the flight
        waiter.complete().await;

        // New acquire should be leader again
        let result2 = sf.try_acquire(&key).await;
        assert!(
            matches!(result2, FlightResult::Leader { .. }),
            "after complete, new acquire should return Leader"
        );
    }

    #[tokio::test]
    async fn test_follower_receives_notification() {
        let sf = Arc::new(SingleFlight::new());
        let key = test_key();

        // Leader acquires
        let result1 = sf.try_acquire(&key).await;
        let waiter = match result1 {
            FlightResult::Leader { waiter } => waiter,
            _ => panic!("expected Leader"),
        };

        // Follower acquires
        let result2 = sf.try_acquire(&key).await;
        let mut receiver = match result2 {
            FlightResult::Follower { receiver } => receiver,
            _ => panic!("expected Follower"),
        };

        // Leader completes in a separate task
        let handle = tokio::spawn(async move {
            waiter.complete().await;
        });

        // Follower should receive notification
        let recv_result = receiver.recv().await;
        assert!(recv_result.is_ok(), "follower should receive notification");

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_cancel_removes_entry() {
        let sf = SingleFlight::new();
        let key = test_key();

        // Acquire leadership
        let result1 = sf.try_acquire(&key).await;
        assert!(matches!(result1, FlightResult::Leader { .. }));

        // Cancel
        sf.cancel(&key).await;

        // Drop the old leader (it's already been removed from registry by cancel)
        drop(result1);

        // New acquire should be leader
        let result2 = sf.try_acquire(&key).await;
        assert!(
            matches!(result2, FlightResult::Leader { .. }),
            "after cancel, new acquire should return Leader"
        );
    }

    #[tokio::test]
    async fn test_different_keys_both_leaders() {
        let sf = SingleFlight::new();
        let key1 = CacheKey::new("bucket", "key1");
        let key2 = CacheKey::new("bucket", "key2");

        let result1 = sf.try_acquire(&key1).await;
        let result2 = sf.try_acquire(&key2).await;

        assert!(matches!(result1, FlightResult::Leader { .. }));
        assert!(matches!(result2, FlightResult::Leader { .. }));
    }

    #[tokio::test]
    async fn test_drop_without_complete_wakes_followers() {
        let sf = SingleFlight::new();
        let key = test_key();

        // Leader acquires
        let result1 = sf.try_acquire(&key).await;
        let waiter = match result1 {
            FlightResult::Leader { waiter } => waiter,
            _ => panic!("expected Leader"),
        };

        // Follower acquires
        let result2 = sf.try_acquire(&key).await;
        let mut receiver = match result2 {
            FlightResult::Follower { receiver } => receiver,
            _ => panic!("expected Follower"),
        };

        // Drop without calling complete
        drop(waiter);

        // Follower should get an error (channel closed)
        let recv_result = receiver.recv().await;
        // Could be Ok(()) if send happened before drop, or Err(Closed) if sender was dropped
        // Either way, the follower is unblocked
        assert!(
            recv_result.is_ok() || matches!(recv_result, Err(broadcast::error::RecvError::Closed)),
            "follower should be unblocked when leader is dropped"
        );
    }
}
