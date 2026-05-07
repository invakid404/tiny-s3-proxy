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
///
/// The `work_fn` invocation is deferred into the spawned task body
/// (`async move { work_fn(path).await }`) rather than called directly in the
/// pump. That isolates synchronous panics inside `work_fn` (e.g. its outer
/// closure body, before the first `await`) inside the spawned task, where
/// `JoinSet` converts them into `JoinError` and `map_join_error` translates
/// them into the caller's error type. Calling `work_fn` directly in the pump
/// would let a synchronous panic unwind the caller's task instead.
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
    assert!(
        max_in_flight > 0,
        "bounded_parallel_scan requires max_in_flight > 0"
    );
    let cap = max_in_flight;
    let mut join_set: tokio::task::JoinSet<Result<T, E>> = tokio::task::JoinSet::new();
    let mut iter = paths.into_iter();
    let mut results = Vec::new();

    for path in iter.by_ref().take(cap) {
        let work_fn = work_fn.clone();
        join_set.spawn(async move { work_fn(path).await });
    }

    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok(Ok(value)) => {
                results.push(value);
                if let Some(next_path) = iter.next() {
                    let work_fn = work_fn.clone();
                    join_set.spawn(async move { work_fn(next_path).await });
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

        let started = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        // Zero-permit semaphore: every spawned shard parks until we release.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let work_fn = {
            let started = started.clone();
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            let gate = gate.clone();
            move |_path: PathBuf| {
                let started = started.clone();
                let in_flight = in_flight.clone();
                let max_seen = max_seen.clone();
                let gate = gate.clone();
                async move {
                    // Increment runs on the spawned task's first poll, BEFORE
                    // the gate await — so it counts shards that the pump
                    // actually spawned, even with the deferred-invocation
                    // shape (`spawn(async move { work_fn(path).await })`).
                    started.fetch_add(1, Ordering::SeqCst);
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

        // Yield until exactly N shard futures have started. With the gate
        // closed, no shard can finish, so the pump cannot top the set back
        // up beyond its initial seed of N.
        for _ in 0..10_000 {
            if started.load(Ordering::SeqCst) >= N {
                break;
            }
            tokio::task::yield_now().await;
        }

        // Quiesce: extra yields so a buggy implementation has a chance to
        // over-spawn (and have those over-spawned tasks poll past the
        // increment) before we assert the bound.
        for _ in 0..256 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            started.load(Ordering::SeqCst),
            N,
            "exactly N shard futures should have started before any permit is released",
        );

        // Release everything; the pump should now drain all paths.
        gate.add_permits(TOTAL);

        let results = scan_handle.await.expect("scan task").expect("scan ok");
        assert_eq!(results.len(), TOTAL);
        assert_eq!(started.load(Ordering::SeqCst), TOTAL);
        assert!(
            max_seen.load(Ordering::SeqCst) <= N,
            "max in-flight {} exceeded cap {}",
            max_seen.load(Ordering::SeqCst),
            N,
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }

    /// Locks in the deferred-invocation contract for `work_fn`: a
    /// synchronous panic from `work_fn` (before its returned future is
    /// produced) must surface as `Err(map_join_error(JoinError))` rather
    /// than unwinding the caller's task.
    ///
    /// Under the deferred shape (`spawn(async move { work_fn(path).await })`)
    /// the `work_fn` call happens inside the spawned task, so `JoinSet`
    /// catches the panic and reports it as a `JoinError`. Under the
    /// pre-fix shape (`spawn(work_fn(path))`) the call happens in the
    /// pump's task, so the panic unwinds out of `bounded_parallel_scan`
    /// itself and never reaches `map_join_error`.
    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_panic_in_work_fn_surfaces_as_mapped_error() {
        fn panicking_work(_path: PathBuf) -> std::future::Ready<Result<(), &'static str>> {
            panic!("synchronous panic inside work_fn body");
        }

        let paths: Vec<PathBuf> = (0..4).map(|i| PathBuf::from(format!("p{i}"))).collect();

        let scan_handle = tokio::spawn(async move {
            bounded_parallel_scan(paths, 2, panicking_work, |_join_err| "mapped-join-error").await
        });

        let outcome = scan_handle
            .await
            .expect("pump must not unwind into the caller; the panic belongs in JoinError");
        assert_eq!(
            outcome,
            Err("mapped-join-error"),
            "synchronous panic should surface through map_join_error",
        );
    }

    /// `max_in_flight = 0` is programmer error: `take(0)` would silently
    /// process nothing and return `Ok(Vec::new())`, dropping every input
    /// path. Lock in the explicit assert that catches the misuse instead of
    /// the prior `.max(1)` coercion (which violated the documented "at most
    /// `max_in_flight`" contract).
    #[tokio::test]
    #[should_panic(expected = "bounded_parallel_scan requires max_in_flight > 0")]
    async fn bounded_parallel_scan_rejects_zero_concurrency() {
        // Non-empty paths so it's clear that a zero cap would drop work.
        let paths = vec![PathBuf::from("a"), PathBuf::from("b")];
        let _ = bounded_parallel_scan(
            paths,
            0,
            |_p| async { Ok::<(), std::convert::Infallible>(()) },
            |e| -> std::convert::Infallible { panic!("unexpected join error: {e}") },
        )
        .await;
    }
}
