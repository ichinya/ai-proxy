pub mod entropy_scanner;
pub mod regex_scanner;
pub mod structural_scanner;

use std::collections::HashSet;
use tracing::{debug, info};

/// Represents a detected secret match in scanned content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScanMatch {
    /// The matched secret value.
    pub value: String,
    /// Name/type of the scanner that found it.
    pub scanner: String,
    /// Human-readable label for the pattern (e.g. "aws_access_key").
    pub pattern_name: String,
    /// Byte offset in the original text where the match starts.
    pub start: usize,
    /// Byte offset in the original text where the match ends.
    pub end: usize,
}

/// Trait that all secret scanners must implement.
pub trait SecretScanner: Send + Sync {
    /// Scan the given text and return all detected secret matches.
    fn scan(&self, text: &str) -> Vec<ScanMatch>;

    /// Scanner name for logging/identification.
    fn name(&self) -> &str;
}

/// Pipeline that runs multiple scanners and deduplicates results.
pub struct ScanPipeline {
    scanners: Vec<Box<dyn SecretScanner>>,
}

impl ScanPipeline {
    pub fn new() -> Self {
        debug!("Creating empty scan pipeline");
        Self {
            scanners: Vec::new(),
        }
    }

    pub fn add_scanner(&mut self, scanner: Box<dyn SecretScanner>) {
        info!(scanner = scanner.name(), "Adding scanner to pipeline");
        self.scanners.push(scanner);
    }

    /// Run all scanners on the text, deduplicating by matched value.
    /// Earlier scanner results take priority (first match wins for a given value).
    pub fn scan(&self, text: &str) -> Vec<ScanMatch> {
        debug!(
            text_len = text.len(),
            scanner_count = self.scanners.len(),
            "Running scan pipeline"
        );

        let mut seen_values: HashSet<String> = HashSet::new();
        let mut results: Vec<ScanMatch> = Vec::new();

        for scanner in &self.scanners {
            let matches = scanner.scan(text);
            debug!(
                scanner = scanner.name(),
                matches_found = matches.len(),
                "Scanner completed"
            );

            for m in matches {
                if seen_values.insert(m.value.clone()) {
                    results.push(m);
                }
            }
        }

        info!(
            total_unique_matches = results.len(),
            "Scan pipeline completed"
        );
        results
    }
}

impl Default for ScanPipeline {
    fn default() -> Self {
        Self::new()
    }
}
