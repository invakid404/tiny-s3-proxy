//! Bounded streaming `JoinSet` pump shared by the startup and eviction
//! filesystem scans.
//!
//! Both scans enumerate `objects/XX/YY/` shards eagerly into a `Vec<PathBuf>`
//! and then need to process those shards concurrently with a hard ceiling on
//! how many shard tasks are alive at once. A naive `JoinSet::spawn` over the
//! full vector would put every shard on the runtime up front (≤ 65k tasks on
//! a fully fragmented cache) before any of them get to run; this module keeps
//! at most `max_in_flight` tasks live by spawning the next shard only after
//! `join_next` has yielded a slot.
//!
//! Fail-fast: the first per-shard `Err` (or a `JoinError`) drops the
//! `JoinSet`, which aborts in-flight shard tasks. Shards that have not yet
//! been spawned never start.
use std::future::Future;
use std::path::PathBuf;

/// Maximum number of hash-directory shard tasks alive at once during a
/// startup or eviction scan.
pub(super) const CACHE_HASH_DIR_SCAN_CONCURRENCY: usize = 64;

/// Process `paths` with at most `max_in_flight` shard tasks alive at once.
///
/// `work_fn` is invoked once per path to produce the per-shard future, which
/// is spawned on a `JoinSet`. The pump tops the set back up to
/// `max_in_flight` after each `join_next`. On the first `Err` from a shard
/// or a `JoinError`, the `JoinSet` is dropped — aborting in-flight shards —
/// and unspawned paths never start. `map_join_error` lets the caller adapt
/// `JoinError` to its own error type.
pub(super) async fn bounded_parallel_scan<T, E, F, Fut, J>(
    paths: Vec<PathBuf>,
    max_in_flight: usize,
    work_fn: F,
    map_join_error: J,
) -> Result<Vec<T>, E>
where
    T: Send + 'static,
    E: Send + 'static,
    F: Fn(PathBuf) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    J: Fn(tokio::task::JoinError) -> E,
{
    let cap = max_in_flight.max(1);
    let mut join_set: tokio::task::JoinSet<Result<T, E>> = tokio::task::JoinSet::new();
    let mut iter = paths.into_iter();
    let mut results = Vec::new();

    for path in iter.by_ref().take(cap) {
        join_set.spawn(work_fn(path));
    }

    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok(Ok(value)) => {
                results.push(value);
                if let Some(next_path) = iter.next() {
                    join_set.spawn(work_fn(next_path));
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(map_join_error(e)),
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_parallel_scan_caps_in_flight_shards() {
        const N: usize = 8;
        const TOTAL: usize = 200;

        let constructed = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        // Zero-permit semaphore: every spawned shard parks until we release.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let work_fn = {
            let constructed = constructed.clone();
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            let gate = gate.clone();
            move |_path: PathBuf| {
                // Synchronous: counts at construction time, BEFORE any await.
                constructed.fetch_add(1, Ordering::SeqCst);
                let in_flight = in_flight.clone();
                let max_seen = max_seen.clone();
                let gate = gate.clone();
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(now, Ordering::SeqCst);
                    let permit = gate.acquire_owned().await.expect("gate not closed");
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    drop(permit);
                    Ok::<usize, ()>(0)
                }
            }
        };

        let paths: Vec<PathBuf> = (0..TOTAL).map(|i| PathBuf::from(format!("p{i}"))).collect();

        let scan_handle =
            tokio::spawn(async move { bounded_parallel_scan(paths, N, work_fn, |_| ()).await });

        // Yield until the pump has constructed exactly N shard futures.
        // Constructed is incremented synchronously inside work_fn, so we never
        // need a sleep — the scheduler progressing the pump task is enough.
        for _ in 0..10_000 {
            if constructed.load(Ordering::SeqCst) >= N {
                break;
            }
            tokio::task::yield_now().await;
        }

        // Quiesce: a few more yields to give a buggy implementation a chance
        // to over-spawn before we assert the bound.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            constructed.load(Ordering::SeqCst),
            N,
            "exactly N shard futures should be constructed before any permit is released",
        );

        // Release everything; the pump should now drain all paths.
        gate.add_permits(TOTAL);

        let results = scan_handle.await.expect("scan task").expect("scan ok");
        assert_eq!(results.len(), TOTAL);
        assert_eq!(constructed.load(Ordering::SeqCst), TOTAL);
        assert!(
            max_seen.load(Ordering::SeqCst) <= N,
            "max in-flight {} exceeded cap {}",
            max_seen.load(Ordering::SeqCst),
            N,
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }
}
