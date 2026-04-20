use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub content_rules: Vec<ContentRuleDef>,
    #[serde(default)]
    pub path_rules: Vec<PathRuleDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContentRuleDef {
    pub id: String,
    pub description: String,
    pub regex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathRuleDef {
    pub id: String,
    pub description: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

const BUILTIN_RULES: &str = include_str!("builtin.toml");
const WEB3_RULES: &str = include_str!("web3.toml");

pub fn load_rules() -> Result<(Vec<ContentRuleDef>, Vec<PathRuleDef>)> {
    let builtin: RuleFile = toml::from_str(BUILTIN_RULES)?;
    let web3: RuleFile = toml::from_str(WEB3_RULES)?;

    let mut content_rules = builtin.content_rules;
    content_rules.extend(web3.content_rules);

    let mut path_rules = builtin.path_rules;
    path_rules.extend(web3.path_rules);

    Ok((content_rules, path_rules))
}
