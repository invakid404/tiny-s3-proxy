use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a lightweight request ID using process ID + monotonic counter.
/// Format: "{pid}-{counter}" — unique per process, no heap allocation needed
/// for the counter part, but we return String for compatibility.
pub fn generate() -> String {
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{pid}-{count}")
}
