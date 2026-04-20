use std::fs;
use std::path::Path;

use anyhow::Result;

use super::{GenerateResult, IgnoreGenerator};

pub struct ClaudeGenerator;

impl IgnoreGenerator for ClaudeGenerator {
    fn tool_name(&self) -> &str {
        "Claude Code"
    }

    fn is_installed(&self, project_dir: &Path) -> bool {
        project_dir.join(".claude").exists()
    }

    fn generate(&self, patterns: &[String], project_dir: &Path) -> Result<GenerateResult> {
        let claude_dir = project_dir.join(".claude");
        let settings_path = claude_dir.join("settings.json");

        // Read existing settings or create new
        let mut settings: serde_json::Value = if settings_path.exists() {
            let content = fs::read_to_string(&settings_path)?;
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
        } else {
            fs::create_dir_all(&claude_dir)?;
            serde_json::json!({})
        };

        // Get or create permissions.deny array
        let deny = settings
            .as_object_mut()
            .unwrap()
            .entry("permissions")
            .or_insert(serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .entry("deny")
            .or_insert(serde_json::json!([]))
            .as_array_mut()
            .unwrap();

        let existing: Vec<String> = deny
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();

        let mut added = 0;
        for pattern in patterns {
            let rule = format!("Read({})", pattern);
            if !existing.contains(&rule) {
                deny.push(serde_json::Value::String(rule));
                added += 1;
            }
        }

        if added > 0 {
            let content = serde_json::to_string_pretty(&settings)?;
            fs::write(&settings_path, content)?;
        }

        Ok(GenerateResult {
            tool_name: self.tool_name().to_string(),
            config_path: settings_path.display().to_string(),
            patterns_added: added,
        })
    }
}
