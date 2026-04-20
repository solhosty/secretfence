use std::fs;
use std::path::Path;

use anyhow::Result;

use super::{GenerateResult, IgnoreGenerator};

pub struct LlmignoreGenerator;

impl IgnoreGenerator for LlmignoreGenerator {
    fn tool_name(&self) -> &str {
        "Universal"
    }

    fn is_installed(&self, _project_dir: &Path) -> bool {
        true // Always generate .llmignore
    }

    fn generate(&self, patterns: &[String], project_dir: &Path) -> Result<GenerateResult> {
        let ignore_path = project_dir.join(".llmignore");

        let existing = if ignore_path.exists() {
            fs::read_to_string(&ignore_path)?
        } else {
            String::new()
        };

        let existing_lines: Vec<String> = existing.lines().map(String::from).collect();
        let mut new_lines = Vec::new();

        for pattern in patterns {
            if !existing_lines.iter().any(|l| l == pattern) {
                new_lines.push(pattern.clone());
            }
        }

        if !new_lines.is_empty() {
            let mut content = existing;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            if existing_lines.is_empty()
                || !existing_lines
                    .last()
                    .map(|l| l.starts_with("# secretfence"))
                    .unwrap_or(false)
            {
                content.push_str("\n# secretfence — auto-generated deny rules\n");
            }
            for line in &new_lines {
                content.push_str(line.as_str());
                content.push('\n');
            }
            fs::write(&ignore_path, content)?;
        }

        Ok(GenerateResult {
            tool_name: self.tool_name().to_string(),
            config_path: ignore_path.display().to_string(),
            patterns_added: new_lines.len(),
        })
    }
}
