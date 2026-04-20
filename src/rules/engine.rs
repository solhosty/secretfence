use anyhow::Result;
use regex::Regex;
use std::path::Path;

use super::loader::{ContentRuleDef, PathRuleDef};

#[derive(Debug)]
pub struct CompiledContentRule {
    pub id: String,
    pub description: String,
    pub regex: Regex,
}

#[derive(Debug)]
pub struct CompiledPathRule {
    pub id: String,
    pub description: String,
    pub patterns: Vec<glob::Pattern>,
    pub allow: Vec<glob::Pattern>,
}

#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub rule_id: String,
    pub description: String,
    pub line_number: usize,
    pub matched_text: String,
}

#[derive(Debug, Clone)]
pub struct PathMatch {
    pub rule_id: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum SecretMatch {
    Path {
        file_path: String,
        rule_id: String,
        description: String,
    },
    Content {
        file_path: String,
        rule_id: String,
        description: String,
        line_number: usize,
    },
}

impl SecretMatch {
    pub fn file_path(&self) -> &str {
        match self {
            SecretMatch::Path { file_path, .. } => file_path,
            SecretMatch::Content { file_path, .. } => file_path,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            SecretMatch::Path { description, .. } => description,
            SecretMatch::Content { description, .. } => description,
        }
    }

    pub fn rule_id(&self) -> &str {
        match self {
            SecretMatch::Path { rule_id, .. } => rule_id,
            SecretMatch::Content { rule_id, .. } => rule_id,
        }
    }

    pub fn line_number(&self) -> Option<usize> {
        match self {
            SecretMatch::Content { line_number, .. } => Some(*line_number),
            _ => None,
        }
    }
}

pub struct RuleEngine {
    content_rules: Vec<CompiledContentRule>,
    path_rules: Vec<CompiledPathRule>,
}

impl RuleEngine {
    pub fn new(
        content_defs: Vec<ContentRuleDef>,
        path_defs: Vec<PathRuleDef>,
    ) -> Result<Self> {
        let content_rules = content_defs
            .into_iter()
            .filter_map(|def| {
                match Regex::new(&def.regex) {
                    Ok(regex) => Some(CompiledContentRule {
                        id: def.id,
                        description: def.description,
                        regex,
                    }),
                    Err(e) => {
                        eprintln!("Warning: invalid regex for rule {}: {}", def.id, e);
                        None
                    }
                }
            })
            .collect();

        let path_rules = path_defs
            .into_iter()
            .filter_map(|def| {
                let patterns: Vec<_> = def
                    .patterns
                    .iter()
                    .filter_map(|p| glob::Pattern::new(p).ok())
                    .collect();
                let allow: Vec<_> = def
                    .allow
                    .iter()
                    .filter_map(|p| glob::Pattern::new(p).ok())
                    .collect();
                if patterns.is_empty() {
                    None
                } else {
                    Some(CompiledPathRule {
                        id: def.id,
                        description: def.description,
                        patterns,
                        allow,
                    })
                }
            })
            .collect();

        Ok(RuleEngine {
            content_rules,
            path_rules,
        })
    }

    pub fn check_path(&self, path: &Path) -> Option<PathMatch> {
        let file_name = path.file_name()?.to_str()?;
        let path_str = path.to_str()?;

        for rule in &self.path_rules {
            // Check allow list first
            let allowed = rule
                .allow
                .iter()
                .any(|p| p.matches(file_name) || p.matches(path_str));
            if allowed {
                continue;
            }

            let matched = rule
                .patterns
                .iter()
                .any(|p| p.matches(file_name) || p.matches(path_str));
            if matched {
                return Some(PathMatch {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                });
            }
        }
        None
    }

    pub fn check_content(&self, content: &str) -> Vec<ContentMatch> {
        let mut matches = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            for rule in &self.content_rules {
                if let Some(m) = rule.regex.find(line) {
                    // Truncate matched text for display (don't show full secrets)
                    let matched = m.as_str();
                    let display = if matched.len() > 20 {
                        format!("{}...", &matched[..20])
                    } else {
                        matched.to_string()
                    };

                    matches.push(ContentMatch {
                        rule_id: rule.id.clone(),
                        description: rule.description.clone(),
                        line_number: line_idx + 1,
                        matched_text: display,
                    });
                    break; // One match per line per rule is enough
                }
            }
        }

        matches
    }

    pub fn path_rules(&self) -> &[CompiledPathRule] {
        &self.path_rules
    }

    pub fn content_rules(&self) -> &[CompiledContentRule] {
        &self.content_rules
    }

    pub fn denied_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        for rule in &self.path_rules {
            for pattern in &rule.patterns {
                patterns.push(pattern.as_str().to_string());
            }
        }
        patterns
    }
}
