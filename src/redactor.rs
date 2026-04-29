use crate::config::RedactionConfig;
use tracing::{debug, trace};

#[derive(Debug, Clone)]
pub struct Redactor {
    prefix_len: usize,
    suffix_len: usize,
    mask: String,
}

impl Redactor {
    pub fn new(config: &RedactionConfig) -> Self {
        debug!(
            strategy = %config.strategy,
            prefix_len = config.prefix_len,
            suffix_len = config.suffix_len,
            "Initializing redactor"
        );
        Self {
            prefix_len: config.prefix_len,
            suffix_len: config.suffix_len,
            mask: config.mask.clone(),
        }
    }

    /// Mask a secret value using partial mask strategy.
    /// For strings long enough: prefix + mask + suffix.
    /// For short strings: full mask replacement.
    pub fn redact(&self, value: &str) -> String {
        let char_count = value.chars().count();
        let min_visible = self.prefix_len + self.suffix_len;

        if char_count <= min_visible + 2 {
            trace!(
                original_len = value.len(),
                "Secret too short for partial mask, using full mask"
            );
            self.mask.clone()
        } else {
            // Use char boundaries to avoid panics on multi-byte UTF-8
            let prefix: String = value.chars().take(self.prefix_len).collect();
            let suffix: String = value.chars().skip(char_count - self.suffix_len).collect();
            trace!(
                original_len = value.len(),
                prefix = %prefix,
                suffix = %suffix,
                "Applying partial mask"
            );
            format!("{}{}{}", prefix, self.mask, suffix)
        }
    }

    /// Replace all occurrences of `secret` in `text` with its redacted form.
    pub fn redact_in_text(&self, text: &str, secret: &str) -> String {
        let masked = self.redact(secret);
        debug!(
            secret_len = secret.len(),
            masked = %masked,
            "Redacting secret in text"
        );
        text.replace(secret, &masked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionConfig;

    fn test_redactor() -> Redactor {
        Redactor::new(&RedactionConfig {
            strategy: "partial".to_string(),
            prefix_len: 3,
            suffix_len: 3,
            mask: "***...***".to_string(),
        })
    }

    #[test]
    fn test_partial_mask_long_string() {
        let r = test_redactor();
        let result = r.redact("sk-ant-abcdef123456789xyz");
        assert_eq!(result, "sk-***...***xyz");
    }

    #[test]
    fn test_full_mask_short_string() {
        let r = test_redactor();
        // 8 chars = prefix(3) + suffix(3) + 2 = 8, should be full mask
        let result = r.redact("abcdefgh");
        assert_eq!(result, "***...***");
    }

    #[test]
    fn test_full_mask_very_short() {
        let r = test_redactor();
        let result = r.redact("abc");
        assert_eq!(result, "***...***");
    }

    #[test]
    fn test_partial_mask_boundary() {
        let r = test_redactor();
        // 9 chars = prefix(3) + suffix(3) + 3 > min_visible + 2, partial mask
        let result = r.redact("123456789");
        assert_eq!(result, "123***...***789");
    }

    #[test]
    fn test_redact_in_text() {
        let r = test_redactor();
        let text = "My key is sk-ant-abcdef123456789xyz please use it";
        let result = r.redact_in_text(text, "sk-ant-abcdef123456789xyz");
        assert_eq!(result, "My key is sk-***...***xyz please use it");
    }

    #[test]
    fn test_redact_in_text_multiple_occurrences() {
        let r = test_redactor();
        let text = "key1=AKIA1234567890ABCDEF key2=AKIA1234567890ABCDEF";
        let result = r.redact_in_text(text, "AKIA1234567890ABCDEF");
        assert!(result.contains("AKI***...***DEF"));
        assert!(!result.contains("AKIA1234567890ABCDEF"));
    }
}
