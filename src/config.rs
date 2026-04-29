use serde::Deserialize;
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub redaction: RedactionConfig,
    pub scanner: ScannerConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    #[serde(alias = "upstream_url")]
    pub anthropic_upstream_url: String,
    #[serde(default = "default_codex_upstream_url")]
    pub codex_upstream_url: String,
    #[serde(default = "default_codex_subscription_url")]
    pub codex_subscription_url: String,
    #[serde(default = "default_true")]
    pub codex_subscription_routing_enabled: bool,
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u64,
    #[serde(default)]
    pub mitm_enabled: bool,
    #[serde(default)]
    pub mitm_ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub mitm_ca_key_path: Option<PathBuf>,
    #[serde(default = "default_mitm_cert_cache_size")]
    pub mitm_cert_cache_size: usize,
    #[serde(default)]
    pub mitm_excluded_hosts: Vec<String>,
    #[serde(default = "default_websocket_mode")]
    pub websocket_mode: String,
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024
}
fn default_codex_upstream_url() -> String {
    "https://api.openai.com".to_string()
}
fn default_codex_subscription_url() -> String {
    "https://chatgpt.com/backend-api/codex/responses".to_string()
}
fn default_connect_timeout() -> u64 {
    10
}
fn default_request_timeout() -> u64 {
    0
}
fn default_rate_limit_rps() -> u64 {
    50
}
fn default_mitm_cert_cache_size() -> usize {
    256
}
fn default_true() -> bool {
    true
}
fn default_websocket_mode() -> String {
    "inspect".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedactionConfig {
    pub strategy: String,
    pub prefix_len: usize,
    pub suffix_len: usize,
    pub mask: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub scan_scope: String,
    pub header_whitelist: Vec<String>,
    pub regex: RegexScannerConfig,
    pub entropy: EntropyScannerConfig,
    pub structural: StructuralScannerConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegexScannerConfig {
    pub enabled: bool,
    pub patterns: Vec<RegexPattern>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegexPattern {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EntropyScannerConfig {
    pub enabled: bool,
    pub threshold: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub keywords: Vec<String>,
    pub keyword_proximity: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StructuralScannerConfig {
    pub enabled: bool,
    pub detect_jwt: bool,
    pub detect_connection_strings: bool,
    pub detect_env_patterns: bool,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading configuration");

        let content = std::fs::read_to_string(path)?;
        debug!(size_bytes = content.len(), "Config file read");

        let mut config: Config = toml::from_str(&content)?;
        config.apply_env_overrides()?;
        config.validate()?;
        info!(
            listen_addr = %config.proxy.listen_addr,
            anthropic_upstream_url = %config.proxy.anthropic_upstream_url,
            codex_upstream_url = %config.proxy.codex_upstream_url,
            scan_scope = %config.scanner.scan_scope,
            scanner_enabled = config.scanner.enabled,
            rate_limit_enabled = config.proxy.rate_limit_enabled,
            mitm_enabled = config.proxy.mitm_enabled,
            mitm_cert_cache_size = config.proxy.mitm_cert_cache_size,
            mitm_excluded_hosts = config.proxy.mitm_excluded_hosts.len(),
            websocket_mode = %config.proxy.websocket_mode,
            regex_patterns_count = config.scanner.regex.patterns.len(),
            "Configuration loaded successfully"
        );

        Ok(config)
    }

    fn apply_env_overrides(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        override_string("AI_PROXY_LISTEN_ADDR", &mut self.proxy.listen_addr);
        override_string(
            "AI_PROXY_ANTHROPIC_UPSTREAM_URL",
            &mut self.proxy.anthropic_upstream_url,
        );
        override_string(
            "AI_PROXY_UPSTREAM_URL",
            &mut self.proxy.anthropic_upstream_url,
        );
        override_string(
            "AI_PROXY_CODEX_UPSTREAM_URL",
            &mut self.proxy.codex_upstream_url,
        );
        override_string(
            "AI_PROXY_CODEX_SUBSCRIPTION_URL",
            &mut self.proxy.codex_subscription_url,
        );
        override_bool(
            "AI_PROXY_CODEX_SUBSCRIPTION_ROUTING_ENABLED",
            &mut self.proxy.codex_subscription_routing_enabled,
        )?;
        override_parse("AI_PROXY_MAX_BODY_SIZE", &mut self.proxy.max_body_size)?;
        override_parse(
            "AI_PROXY_CONNECT_TIMEOUT_SECS",
            &mut self.proxy.connect_timeout_secs,
        )?;
        override_parse(
            "AI_PROXY_REQUEST_TIMEOUT_SECS",
            &mut self.proxy.request_timeout_secs,
        )?;
        override_parse("AI_PROXY_RATE_LIMIT_RPS", &mut self.proxy.rate_limit_rps)?;
        override_bool(
            "AI_PROXY_RATE_LIMIT_ENABLED",
            &mut self.proxy.rate_limit_enabled,
        )?;
        override_bool("AI_PROXY_MITM_ENABLED", &mut self.proxy.mitm_enabled)?;
        override_optional_path(
            "AI_PROXY_MITM_CA_CERT_PATH",
            &mut self.proxy.mitm_ca_cert_path,
        );
        override_optional_path(
            "AI_PROXY_MITM_CA_KEY_PATH",
            &mut self.proxy.mitm_ca_key_path,
        );
        override_parse(
            "AI_PROXY_MITM_CERT_CACHE_SIZE",
            &mut self.proxy.mitm_cert_cache_size,
        )?;
        override_string_list(
            "AI_PROXY_MITM_EXCLUDED_HOSTS",
            &mut self.proxy.mitm_excluded_hosts,
        );
        override_string("AI_PROXY_WEBSOCKET_MODE", &mut self.proxy.websocket_mode);
        override_bool(
            "AI_PROXY_SECRET_SCANNING_ENABLED",
            &mut self.scanner.enabled,
        )?;
        override_string("AI_PROXY_SCAN_SCOPE", &mut self.scanner.scan_scope);
        override_bool(
            "AI_PROXY_REGEX_SCANNER_ENABLED",
            &mut self.scanner.regex.enabled,
        )?;
        override_bool(
            "AI_PROXY_ENTROPY_SCANNER_ENABLED",
            &mut self.scanner.entropy.enabled,
        )?;
        override_bool(
            "AI_PROXY_STRUCTURAL_SCANNER_ENABLED",
            &mut self.scanner.structural.enabled,
        )?;
        override_string("AI_PROXY_REDACTION_STRATEGY", &mut self.redaction.strategy);
        override_parse(
            "AI_PROXY_REDACTION_PREFIX_LEN",
            &mut self.redaction.prefix_len,
        )?;
        override_parse(
            "AI_PROXY_REDACTION_SUFFIX_LEN",
            &mut self.redaction.suffix_len,
        )?;
        override_string("AI_PROXY_REDACTION_MASK", &mut self.redaction.mask);

        Ok(())
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.proxy.rate_limit_enabled
            && (self.proxy.rate_limit_rps == 0 || self.proxy.rate_limit_rps > u32::MAX as u64)
        {
            return Err(config_error(
                "proxy.rate_limit_rps must be between 1 and 4294967295 when rate limiting is enabled",
            ));
        }

        if self.scanner.enabled
            && self.scanner.scan_scope != "body"
            && self.scanner.scan_scope != "full"
        {
            return Err(config_error(
                "scanner.scan_scope must be either 'body' or 'full'",
            ));
        }

        if self.proxy.mitm_enabled {
            info!(
                cert_path_set = self.proxy.mitm_ca_cert_path.is_some(),
                key_path_set = self.proxy.mitm_ca_key_path.is_some(),
                "MITM inspection enabled"
            );

            if self.proxy.mitm_ca_cert_path.is_none() {
                warn!("MITM is enabled but proxy.mitm_ca_cert_path is missing");
                return Err(config_error(
                    "proxy.mitm_ca_cert_path is required when proxy.mitm_enabled is true",
                ));
            }

            if self.proxy.mitm_ca_key_path.is_none() {
                warn!("MITM is enabled but proxy.mitm_ca_key_path is missing");
                return Err(config_error(
                    "proxy.mitm_ca_key_path is required when proxy.mitm_enabled is true",
                ));
            }

            if self.proxy.mitm_cert_cache_size == 0 {
                warn!("MITM certificate cache size must be greater than zero");
                return Err(config_error(
                    "proxy.mitm_cert_cache_size must be greater than zero when proxy.mitm_enabled is true",
                ));
            }
        } else {
            info!("MITM inspection disabled; CONNECT requests use blind tunneling");
        }

        if self.proxy.websocket_mode != "reject"
            && self.proxy.websocket_mode != "passthrough"
            && self.proxy.websocket_mode != "inspect"
        {
            return Err(config_error(
                "proxy.websocket_mode must be one of 'reject', 'passthrough', or 'inspect'",
            ));
        }

        Ok(())
    }
}

fn config_error(message: &str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn override_string(var_name: &str, target: &mut String) {
    if let Ok(value) = env::var(var_name) {
        *target = value;
    }
}

fn override_optional_path(var_name: &str, target: &mut Option<PathBuf>) {
    let Ok(value) = env::var(var_name) else {
        return;
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        *target = None;
    } else {
        *target = Some(PathBuf::from(trimmed));
    }
}

fn override_string_list(var_name: &str, target: &mut Vec<String>) {
    let Ok(value) = env::var(var_name) else {
        return;
    };

    *target = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();
}

fn override_parse<T>(var_name: &str, target: &mut T) -> Result<(), Box<dyn std::error::Error>>
where
    T: FromStr,
    T::Err: std::error::Error + 'static,
{
    let Ok(value) = env::var(var_name) else {
        return Ok(());
    };

    *target = value.parse::<T>()?;
    Ok(())
}

fn override_bool(var_name: &str, target: &mut bool) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(value) = env::var(var_name) else {
        return Ok(());
    };

    let normalized = value.trim().to_ascii_lowercase();
    *target = match normalized.as_str() {
        "1" | "true" | "on" | "yes" => true,
        "0" | "false" | "off" | "no" => false,
        _ => {
            return Err(config_error(&format!(
                "{var_name} must be one of true/false, 1/0, on/off, yes/no"
            )));
        }
    };
    Ok(())
}
