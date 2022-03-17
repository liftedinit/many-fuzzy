use hdrhistogram::Histogram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

#[derive(Default, Clone)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    pub fn load(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A statistics holder.
#[derive(Clone)]
pub struct Statistics {
    pub histogram: Arc<Mutex<Histogram<u64>>>,
    pub request_counter: Counter,
    pub response_counter: Counter,
    pub http_errors_counter: Counter,
    pub many_errors_counter: Counter,
    pub many_success_counter: Counter,
}

impl Default for Statistics {
    fn default() -> Self {
        Statistics {
            histogram: Arc::new(Mutex::new(
                Histogram::<u64>::new_with_bounds(1, 300_000_000_000, 3)
                    .expect("Could not create a histogram"),
            )),
            request_counter: Default::default(),
            response_counter: Default::default(),
            http_errors_counter: Default::default(),
            many_errors_counter: Default::default(),
            many_success_counter: Default::default(),
        }
    }
}

impl Statistics {
    pub async fn histogram(&self) -> MutexGuard<'_, Histogram<u64>> {
        self.histogram.lock().await
    }
}
