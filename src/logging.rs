use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::middleware::ScanMatch;

/// Initialize structured logging with configurable log level via RUST_LOG env var.
/// Defaults to "info" if RUST_LOG is not set.
pub fn init_logging() {
    if !logging_enabled_from_env() {
        return;
    }

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true).with_thread_ids(false))
        .init();

    info!("Logging initialized");
}

pub fn logging_enabled_from_env() -> bool {
    std::env::var("AI_PROXY_LOGGING_ENABLED")
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            !matches!(normalized.as_str(), "0" | "false" | "off" | "no")
        })
        .unwrap_or(true)
}

/// Log a redaction event for audit purposes.
pub fn log_redaction(scan_match: &ScanMatch, replacement_len: usize) {
    info!(
        scanner = %scan_match.scanner,
        pattern = %scan_match.pattern_name,
        category = %scan_match.category,
        sensitivity_class = %scan_match.sensitivity_class,
        confidence = scan_match.confidence,
        original_len = scan_match.value.len(),
        replacement_len,
        position_start = scan_match.start,
        position_end = scan_match.end,
        "Secret redacted"
    );
}
