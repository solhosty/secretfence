use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub rules: Option<RulesConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub extra_deny_paths: Vec<String>,
    #[serde(default)]
    pub extra_deny_env: Vec<String>,
    #[serde(default)]
    pub allow: Option<AllowConfig>,
    #[serde(default)]
    pub custom: Vec<CustomRule>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AllowConfig {
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub regex: String,
}

pub fn load_config(project_dir: &Path) -> Config {
    let config_path = project_dir.join(".secretfencerc");
    if !config_path.exists() {
        return Config::default();
    }

    match fs::read_to_string(&config_path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

pub fn init_config(project_dir: &Path) -> Result<()> {
    let config_path = project_dir.join(".secretfencerc");
    if config_path.exists() {
        println!("  .secretfencerc already exists.");
        return Ok(());
    }

    let template = r#"# secretfence configuration
# https://github.com/Cyfrin/secretfence

# Default sandbox profile (generic, web3, or custom)
# profile = "generic"

# Additional rules
# [rules]
# extra_deny_paths = ["my-custom-secrets.yaml"]
# extra_deny_env = ["MY_APP_MASTER_KEY"]

# Files to exclude from detection
# [rules.allow]
# paths = [".env.example", "test/fixtures/.env.test"]

# Custom content detection rules
# [[rules.custom]]
# id = "internal-api-key"
# description = "Internal API key format"
# regex = "INTERNAL_[A-Z]+_KEY=[A-Za-z0-9]{32}"
"#;

    fs::write(&config_path, template)?;
    println!("  Created .secretfencerc");
    Ok(())
}
