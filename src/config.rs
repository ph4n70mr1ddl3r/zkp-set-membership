//! Configuration file support for ZKP set membership system.
//!
//! This module provides configuration file loading from TOML format,
//! allowing for easier deployment and configuration management.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_MAX_ACCOUNTS_FILE_SIZE: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_PROOF_FILE_SIZE: u64 = 1024 * 1024;
const DEFAULT_MAX_ZK_PROOF_SIZE: usize = 512 * 1024;
const DEFAULT_TIMESTAMP_TOLERANCE_SECS: u64 = 300;
const DEFAULT_TIMESTAMP_MAX_AGE_SECS: u64 = 86400;

/// Configuration for the ZKP set membership system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub accounts: AccountsConfig,
    #[serde(default)]
    pub proof: ProofConfig,
    #[serde(default)]
    pub keys: KeysConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsConfig {
    #[serde(default = "default_max_accounts_file_size")]
    pub max_file_size: u64,
    #[serde(default)]
    pub default_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    #[serde(default = "default_max_proof_file_size")]
    pub max_file_size: u64,
    #[serde(default = "default_max_zk_proof_size")]
    pub max_zk_proof_size: usize,
    #[serde(default = "default_proof_output_file")]
    pub output_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysConfig {
    #[serde(default = "default_keys_dir")]
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub enable_persistence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_timestamp_tolerance_secs")]
    pub timestamp_tolerance_secs: u64,
    #[serde(default = "default_timestamp_max_age_secs")]
    pub timestamp_max_age_secs: u64,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_ACCOUNTS_FILE_SIZE,
            default_file: None,
        }
    }
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_PROOF_FILE_SIZE,
            max_zk_proof_size: DEFAULT_MAX_ZK_PROOF_SIZE,
            output_file: PathBuf::from("proof.json"),
        }
    }
}

impl Default for KeysConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from(".keys"),
            enable_persistence: true,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            timestamp_tolerance_secs: DEFAULT_TIMESTAMP_TOLERANCE_SECS,
            timestamp_max_age_secs: DEFAULT_TIMESTAMP_MAX_AGE_SECS,
        }
    }
}

fn default_max_accounts_file_size() -> u64 {
    DEFAULT_MAX_ACCOUNTS_FILE_SIZE
}

fn default_max_proof_file_size() -> u64 {
    DEFAULT_MAX_PROOF_FILE_SIZE
}

fn default_max_zk_proof_size() -> usize {
    DEFAULT_MAX_ZK_PROOF_SIZE
}

fn default_proof_output_file() -> PathBuf {
    PathBuf::from("proof.json")
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from(".keys")
}

fn default_timestamp_tolerance_secs() -> u64 {
    DEFAULT_TIMESTAMP_TOLERANCE_SECS
}

fn default_timestamp_max_age_secs() -> u64 {
    DEFAULT_TIMESTAMP_MAX_AGE_SECS
}

impl Config {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    pub fn load_from_file_or_default(path: &PathBuf) -> Self {
        Self::load_from_file(path).unwrap_or_default()
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config to TOML")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(
            config.accounts.max_file_size,
            DEFAULT_MAX_ACCOUNTS_FILE_SIZE
        );
        assert_eq!(config.proof.max_file_size, DEFAULT_MAX_PROOF_FILE_SIZE);
        assert_eq!(
            config.security.timestamp_tolerance_secs,
            DEFAULT_TIMESTAMP_TOLERANCE_SECS
        );
    }

    #[test]
    fn test_serialize_deserialize_config() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(
            config.accounts.max_file_size,
            deserialized.accounts.max_file_size
        );
        assert_eq!(config.proof.output_file, deserialized.proof.output_file);
    }

    #[test]
    fn test_custom_config() {
        let config_toml = r#"
            [accounts]
            max_file_size = 20485760

            [proof]
            output_file = "custom_proof.json"

            [security]
            timestamp_tolerance_secs = 600
        "#;

        let config: Config = toml::from_str(config_toml).unwrap();
        assert_eq!(config.accounts.max_file_size, 20485760);
        assert_eq!(config.proof.output_file, PathBuf::from("custom_proof.json"));
        assert_eq!(config.security.timestamp_tolerance_secs, 600);
    }
}
